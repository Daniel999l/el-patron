// Launch a target coin on pump.fun from the CRACKPAD launch wallet.
//
// 1. prepare: check the form, upload picture + metadata to pump.fun's IPFS, save a draft, and return a
//    payment transaction (user -> launch wallet, LAUNCH_FEE_USD worth of SOL, memo "crackpad:<draftId>").
// 2. The user's wallet signs and sends that payment. That is the only thing the user signs.
// 3. submit: we read the payment on-chain (right payer, right amount, right memo), then the launch wallet
//    creates the coin with create_v2. The launch wallet is the coin's on-chain creator, so pump.fun creator
//    fees land there and fund the bounty.
import crypto from 'node:crypto';
import bs58 from 'bs58';
import { createRequire } from 'node:module';
import {
  ComputeBudgetProgram, Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram, TransactionInstruction,
  TransactionMessage, VersionedTransaction,
} from '@solana/web3.js';
import { connection, toKey, pumpUrl } from './solana.js';
import { addLaunch, getLaunch, patchLaunch, liveLaunches } from './db.js';

const pump = createRequire(import.meta.url)('@pump-fun/pump-sdk');
const online = new pump.OnlinePumpSdk(connection);

export class UserError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

// LAUNCHER_PRIVATE_KEY: base58 secret key (Phantom export) or a JSON byte array (solana-keygen file).
function loadLauncher() {
  const raw = (process.env.LAUNCHER_PRIVATE_KEY || '').trim();
  if (!raw) return null;
  try {
    const bytes = raw.startsWith('[') ? Uint8Array.from(JSON.parse(raw)) : bs58.decode(raw);
    return Keypair.fromSecretKey(bytes);
  } catch {
    throw new Error('LAUNCHER_PRIVATE_KEY is not a valid Solana secret key (base58 or JSON array).');
  }
}
const LAUNCHER = loadLauncher();
export const launcherAddress = () => LAUNCHER?.publicKey.toBase58() || null;

const FEE_USD = Number(process.env.LAUNCH_FEE_USD) || 2;
const FEE_SOL_FALLBACK = Number(process.env.LAUNCH_FEE_SOL) || 0.02;
const IPFS_URL = (process.env.PUMP_IPFS_URL || 'https://pump.fun/api/ipfs').trim();
const PRIORITY_MICROLAMPORTS = Number(process.env.PRIORITY_MICROLAMPORTS) || 200_000;
const MEMO_PROGRAM = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
const DRAFT_MS = 15 * 60e3;
const MAX_IMAGE = 2 * 1024 * 1024;

// Coin names that impersonate a wallet, exchange or launchpad are refused. Targets can name anything.
const BRANDS = ['phantom', 'solflare', 'backpack', 'jupiter', 'pump', 'pumpfun', 'raydium', 'binance', 'coinbase', 'metamask', 'trustwallet', 'okx', 'bybit', 'gmgn', 'dexscreener', 'photon', 'axiom', 'bullx', 'crackpad'];
const BRAND_RE = new RegExp(`(^|[^a-z])(${BRANDS.join('|')})([^a-z]|$)`, 'i');

const text = (s, n) => String(s ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);

function sniff(buf) {
  if (!buf || buf.length < 12) return null;
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return { mime: 'image/png', ext: 'png' };
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { mime: 'image/jpeg', ext: 'jpg' };
  if (buf.subarray(0, 4).toString('latin1') === 'GIF8') return { mime: 'image/gif', ext: 'gif' };
  if (buf.subarray(0, 4).toString('latin1') === 'RIFF' && buf.subarray(8, 12).toString('latin1') === 'WEBP') return { mime: 'image/webp', ext: 'webp' };
  return null;
}

export function readInput(body) {
  const target = text(body.target, 80);
  const description = text(body.description, 400);
  const name = text(body.name, 32);
  const ticker = text(body.ticker, 10).replace(/^\$/, '').toUpperCase();
  const targetUrl = text(body.targetUrl, 200);
  if (targetUrl && !/^https?:\/\/\S+$/i.test(targetUrl)) throw new UserError('The target link must start with http:// or https://.');
  if (target.length < 2) throw new UserError('Name the target.');
  if (description.length < 4) throw new UserError('Say what should get cracked.');
  if (name.length < 2) throw new UserError('Give the coin a name.');
  if (!/^[A-Z0-9]{2,10}$/.test(ticker)) throw new UserError('The ticker must be 2 to 10 letters or numbers.');
  if (BRAND_RE.test(name) || BRAND_RE.test(ticker)) throw new UserError('The coin name cannot be a wallet, exchange or launchpad name. Put that in the target instead.');
  const owner = toKey(body.owner);
  if (!owner) throw new UserError('Connect your wallet first.');
  return { target, targetUrl: targetUrl || null, description, name, ticker, owner };
}

// ---------- launch fee in SOL (LAUNCH_FEE_USD at the current price, cached 5 minutes) ----------

let priceCache = null;
async function solUsd() {
  if (priceCache && Date.now() - priceCache.at < 5 * 60e3) return priceCache.usd;
  try {
    const r = await fetch('https://lite-api.jup.ag/price/v3?ids=So11111111111111111111111111111111111111112', { signal: AbortSignal.timeout(8000) });
    const usd = Number((await r.json())?.So11111111111111111111111111111111111111112?.usdPrice);
    if (usd > 1) { priceCache = { at: Date.now(), usd }; return usd; }
  } catch {}
  return null;
}
export async function launchFeeLamports() {
  const usd = await solUsd();
  const sol = usd ? FEE_USD / usd : FEE_SOL_FALLBACK;
  return Math.ceil(sol * 1e6) * 1000; // round up to 0.000001 SOL
}

// ---------- pump.fun ----------

// pump.fun's metadata upload: multipart -> { metadataUri, metadata: { image, ... } }
async function uploadMeta({ image, kind, name, ticker, description, website, twitter }) {
  const fd = new FormData();
  fd.append('file', new Blob([image], { type: kind.mime }), `coin.${kind.ext}`);
  fd.append('name', name);
  fd.append('symbol', ticker);
  fd.append('description', description);
  if (website) fd.append('website', website);
  if (twitter) fd.append('twitter', twitter);
  fd.append('showName', 'true');
  const res = await fetch(IPFS_URL, { method: 'POST', body: fd, signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`ipfs ${res.status}`);
  const j = await res.json();
  if (!j?.metadataUri) throw new Error('ipfs: no metadataUri');
  return { uri: j.metadataUri, image: j.metadata?.image || null };
}

// create_v2 with the launch wallet as payer, signer and creator.
export async function buildCreate({ mint, payer, name, ticker, uri }) {
  const ix = await pump.PUMP_SDK.createV2Instruction({ mint, name, symbol: ticker, uri, creator: payer, user: payer, mayhemMode: false });
  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
  const message = new TransactionMessage({
    payerKey: payer,
    recentBlockhash: blockhash,
    instructions: [
      ComputeBudgetProgram.setComputeUnitLimit({ units: 250_000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: PRIORITY_MICROLAMPORTS }),
      ix,
    ],
  }).compileToV0Message();
  return { tx: new VersionedTransaction(message), blockhash, lastValidBlockHeight };
}

// ---------- step 1: form in, payment transaction out ----------

export async function prepareLaunch({ body, image, siteUrl, x }) {
  if (!LAUNCHER) throw new UserError('Launches are paused right now. Try again soon.', 503);
  const input = readInput(body);
  if (!image?.length) throw new UserError('Add a picture for the coin.');
  if (image.length > MAX_IMAGE) throw new UserError('The picture must be under 2 MB.');
  const kind = sniff(image);
  if (!kind) throw new UserError('The picture must be a PNG, JPG, GIF or WEBP.');

  const fee = await launchFeeLamports();
  const balance = await connection.getBalance(input.owner).catch(() => null);
  if (balance !== null && balance < fee + 10_000) {
    throw new UserError(`You need about ${((fee + 10_000) / LAMPORTS_PER_SOL).toFixed(4)} SOL to launch. Your wallet has ${(balance / LAMPORTS_PER_SOL).toFixed(4)} SOL.`);
  }

  const description = `Target: ${input.target}. ${input.description}${input.targetUrl ? ` ${input.targetUrl}` : ''}`.slice(0, 500);
  let meta;
  try { meta = await uploadMeta({ image, kind, name: input.name, ticker: input.ticker, description, website: siteUrl, twitter: x }); }
  catch (e) { console.error('pump ipfs', e.message); throw new UserError('pump.fun did not take the picture. Try again in a moment.', 502); }

  const draftId = crypto.randomBytes(12).toString('hex');
  const { blockhash } = await connection.getLatestBlockhash('confirmed');
  const payMsg = new TransactionMessage({
    payerKey: input.owner,
    recentBlockhash: blockhash,
    instructions: [
      SystemProgram.transfer({ fromPubkey: input.owner, toPubkey: LAUNCHER.publicKey, lamports: fee }),
      new TransactionInstruction({ programId: MEMO_PROGRAM, keys: [{ pubkey: input.owner, isSigner: true, isWritable: false }], data: Buffer.from(`crackpad:${draftId}`) }),
    ],
  }).compileToV0Message();

  await addLaunch({
    draftId, owner: input.owner.toBase58(), fee,
    name: input.name, ticker: input.ticker, target: input.target, targetUrl: input.targetUrl, description: input.description,
    uri: meta.uri, image: meta.image, status: 'draft', createdAt: Date.now(),
  });
  return { draftId, feeSol: fee / LAMPORTS_PER_SOL, tx: Buffer.from(new VersionedTransaction(payMsg).serialize()).toString('base64') };
}

// ---------- step 2: payment landed, launch it ----------

async function readPayment(sig) {
  for (let i = 0; i < 20; i++) {
    const t = await connection.getTransaction(sig, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 }).catch(() => null);
    if (t) return t;
    await new Promise((r) => setTimeout(r, 1500));
  }
  return null;
}

function checkPayment(t, d) {
  if (!t || t.meta?.err) return 'The payment did not go through.';
  const keys = t.transaction.message.getAccountKeys({ accountKeysFromLookups: t.meta.loadedAddresses }).staticAccountKeys;
  if (keys[0].toBase58() !== d.owner) return 'That payment came from a different wallet.';
  const li = keys.findIndex((k) => k.equals(LAUNCHER.publicKey));
  if (li < 0 || t.meta.postBalances[li] - t.meta.preBalances[li] < d.fee) return 'That payment was too small.';
  const memo = (t.meta.logMessages || []).some((l) => l.includes(`crackpad:${d.draftId}`));
  if (!memo) return 'That payment is for a different launch.';
  return null;
}

async function launchCoin(d) {
  const mintKp = Keypair.generate();
  const { tx, blockhash, lastValidBlockHeight } = await buildCreate({ mint: mintKp.publicKey, payer: LAUNCHER.publicKey, name: d.name, ticker: d.ticker, uri: d.uri });
  tx.sign([LAUNCHER, mintKp]);
  const sig = await connection.sendRawTransaction(tx.serialize(), { skipPreflight: false, maxRetries: 3 });
  await patchLaunch(d.draftId, { mint: mintKp.publicKey.toBase58(), launchSig: sig });
  const res = await connection.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, 'confirmed');
  if (res.value?.err) throw new Error('create failed: ' + JSON.stringify(res.value.err));
  return { mint: mintKp.publicKey.toBase58(), sig };
}

export async function submitLaunch({ draftId, sig }) {
  if (!LAUNCHER) throw new UserError('Launches are paused right now. Try again soon.', 503);
  const d = await getLaunch(String(draftId || ''));
  if (!d) throw new UserError('That launch was not found. Start again.', 404);
  if (d.status === 'live') return { status: 'live', mint: d.mint, url: pumpUrl(d.mint) };
  if (d.status === 'launching') return { status: 'launching', error: 'Your coin is being created. Give it a few seconds.' };

  // A paid draft that failed to launch can be retried without paying again.
  if (d.status !== 'paid') {
    if (Date.now() - d.createdAt > DRAFT_MS) throw new UserError('That launch expired. Start again.', 410);
    const s = String(sig || '').trim();
    if (!/^[1-9A-HJ-NP-Za-km-z]{64,90}$/.test(s)) throw new UserError('That is not a transaction signature.');
    const why = checkPayment(await readPayment(s), d);
    if (why) throw new UserError(why);
    await patchLaunch(d.draftId, { status: 'paid', paySig: s, paidAt: Date.now() });
  }

  await patchLaunch(d.draftId, { status: 'launching' });
  try {
    const { mint, sig: launchSig } = await launchCoin(d);
    await patchLaunch(d.draftId, { status: 'live', mint, launchSig, launchedAt: Date.now() });
    return { status: 'live', mint, url: pumpUrl(mint) };
  } catch (e) {
    console.error('launch', d.draftId, e.message);
    await patchLaunch(d.draftId, { status: 'paid', error: e.message });
    throw new UserError('Payment received, but the coin did not launch yet. Press Launch again to retry. You will not pay twice.', 502);
  }
}

export async function boardCoins() {
  return (await liveLaunches(null)).map(({ mint, name, ticker, target, targetUrl, description, image, launchedAt, cracked }) => ({
    mint, name, ticker, target, targetUrl, description, image, launchedAt, cracked: Boolean(cracked), url: pumpUrl(mint),
  }));
}
