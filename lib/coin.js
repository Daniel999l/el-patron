// Coin page data, read live: the mint account (authorities, Token-2022 extensions, on-chain metadata),
// the pump.fun bonding curve (progress, market cap, creator), the creator fee vault (the bounty pot),
// DexScreener (price, volume, trades) and the biggest holders. Plus the REA teardown verdict.
import { createRequire } from 'node:module';
import { LAMPORTS_PER_SOL, PublicKey } from '@solana/web3.js';
import {
  TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, ExtensionType, unpackMint, getExtensionTypes, getExtensionData,
  getAssociatedTokenAddressSync, getTransferFeeConfig, getPermanentDelegate, getTransferHook, getDefaultAccountState, getPausableConfig,
} from '@solana/spl-token';
import { unpack as unpackTokenMetadata } from '@solana/spl-token-metadata';
import { connection, toKey, pumpUrl } from './solana.js';
import { launchByMint } from './db.js';

const pump = createRequire(import.meta.url)('@pump-fun/pump-sdk');
const online = new pump.OnlinePumpSdk(connection);

export class CoinError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

const cache = new Map();
const num = (bn) => Number(bn?.toString?.() ?? bn ?? 0);

async function dexscreener(mint) {
  try {
    const r = await fetch(`https://api.dexscreener.com/tokens/v1/solana/${mint}`, { signal: AbortSignal.timeout(8000) });
    const pairs = await r.json();
    if (!Array.isArray(pairs) || !pairs.length) return null;
    const p = pairs.sort((a, b) => (b.liquidity?.usd || 0) - (a.liquidity?.usd || 0))[0];
    return {
      dex: p.dexId, url: p.url, priceUsd: Number(p.priceUsd) || null, marketCap: p.marketCap ?? p.fdv ?? null,
      liquidityUsd: p.liquidity?.usd ?? null, volume24h: p.volume?.h24 ?? null, change24h: p.priceChange?.h24 ?? null,
      buys24h: p.txns?.h24?.buys ?? null, sells24h: p.txns?.h24?.sells ?? null, image: p.info?.imageUrl || null,
    };
  } catch { return null; }
}

async function metaJson(uri) {
  if (!/^https?:\/\//.test(uri || '')) return null;
  try {
    const r = await fetch(uri, { signal: AbortSignal.timeout(6000) });
    const j = await r.json();
    return { image: typeof j.image === 'string' ? j.image : null, description: typeof j.description === 'string' ? j.description.slice(0, 600) : null };
  } catch { return null; }
}

async function holders(mint) {
  try {
    const res = await connection.getTokenLargestAccounts(mint);
    return res.value.slice(0, 10).map((a) => ({ account: a.address.toBase58(), amount: Number(a.uiAmountString || a.uiAmount || 0) }));
  } catch { return null; } // the public RPC refuses this call; set RPC_URL to a keyed RPC
}

// ---------- REA teardown of the mint ----------

function teardown(mintInfo, programId, extTypes, mintAcc, updateAuthority) {
  const checks = [];
  const add = (level, title, detail) => checks.push({ level, title, detail });
  if (mintInfo.mintAuthority) add('bad', 'More coins can be minted', `Mint authority: ${mintInfo.mintAuthority.toBase58()}`);
  else add('good', 'Supply is fixed', 'No one can mint more.');
  if (mintInfo.freezeAuthority) add('bad', 'Wallets can be frozen', `Freeze authority: ${mintInfo.freezeAuthority.toBase58()}`);
  else add('good', 'No freeze', 'No one can freeze your coins.');
  if (programId.equals(TOKEN_2022_PROGRAM_ID)) {
    const fee = getTransferFeeConfig(mintAcc);
    if (fee) {
      const bps = Number(fee.newerTransferFee.transferFeeBasisPoints);
      add(bps > 0 ? 'bad' : 'warn', bps > 0 ? `Transfer tax ${bps / 100}%` : 'Transfer tax can be switched on', fee.transferFeeConfigAuthority ? `Tax authority: ${fee.transferFeeConfigAuthority.toBase58()}` : 'Tax settings are locked.');
    }
    const pd = getPermanentDelegate(mintAcc);
    if (pd?.delegate && !pd.delegate.equals(PublicKey.default)) add('bad', 'Someone can move anyone\'s coins', `Permanent delegate: ${pd.delegate.toBase58()}`);
    const hook = getTransferHook(mintAcc);
    if (hook?.programId && !hook.programId.equals(PublicKey.default)) add('bad', 'Every transfer runs outside code', `Transfer hook program: ${hook.programId.toBase58()}`);
    const das = getDefaultAccountState(mintAcc);
    if (das && das.state === 2) add('bad', 'New holders start frozen', 'Default account state is frozen.');
    const pause = getPausableConfig?.(mintAcc);
    if (pause) add(pause.paused ? 'bad' : 'warn', pause.paused ? 'Trading is paused' : 'Transfers can be paused', pause.authority ? `Pause authority: ${pause.authority.toBase58()}` : '');
  }
  if (updateAuthority) add('warn', 'Name and picture can be changed', `Update authority: ${updateAuthority}`);
  const known = new Set([ExtensionType.MetadataPointer, ExtensionType.TokenMetadata, ExtensionType.TransferFeeConfig, ExtensionType.PermanentDelegate, ExtensionType.TransferHook, ExtensionType.DefaultAccountState]);
  const other = extTypes.filter((t) => !known.has(t)).map((t) => ExtensionType[t] || String(t));
  if (other.length) add('warn', 'Other token extensions', other.join(', '));
  const bad = checks.filter((c) => c.level === 'bad').length;
  const warn = checks.filter((c) => c.level === 'warn').length;
  const verdict = bad ? 'danger' : warn ? 'caution' : 'safe';
  const summary = bad ? 'This coin has levers that can hurt holders. Read the findings.' : warn ? 'No direct danger found, but check the notes.' : 'Fixed supply, no freeze, no hidden token tricks.';
  return { verdict, summary, checks };
}

export async function coinData(raw) {
  const mint = toKey(raw);
  if (!mint) throw new CoinError('That is not a Solana coin address.');
  const key = mint.toBase58();
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < 20_000) return hit.data;

  const acc = await connection.getAccountInfo(mint).catch(() => { throw new CoinError('Solana did not answer. Try again.', 502); });
  if (!acc) throw new CoinError('No coin at that address.', 404);
  const programId = acc.owner;
  if (!programId.equals(TOKEN_PROGRAM_ID) && !programId.equals(TOKEN_2022_PROGRAM_ID)) throw new CoinError('That address is not a coin.');
  const mintInfo = unpackMint(mint, acc, programId);
  const extTypes = programId.equals(TOKEN_2022_PROGRAM_ID) ? getExtensionTypes(mintInfo.tlvData) : [];

  let onchainMeta = null;
  if (extTypes.includes(ExtensionType.TokenMetadata)) {
    try {
      const m = unpackTokenMetadata(getExtensionData(ExtensionType.TokenMetadata, mintInfo.tlvData));
      onchainMeta = { name: m.name, symbol: m.symbol, uri: m.uri, updateAuthority: m.updateAuthority && !m.updateAuthority.equals(PublicKey.default) ? m.updateAuthority.toBase58() : null };
    } catch {}
  }

  const [curve, global, dex, record] = await Promise.all([
    online.fetchBondingCurve(mint).catch(() => null),
    online.fetchGlobal().catch(() => null),
    dexscreener(key),
    launchByMint(key).catch(() => null),
  ]);
  const [meta, top] = await Promise.all([metaJson(onchainMeta?.uri || record?.uri), holders(mint)]);

  let pumpInfo = null;
  if (curve) {
    const initial = num(global?.initialRealTokenReserves) || 793_100_000_000_000;
    const left = num(curve.realTokenReserves);
    const progress = curve.complete ? 100 : Math.max(0, Math.min(100, (1 - left / initial) * 100));
    const mcLamports = curve.complete || curve.virtualTokenReserves.isZero() ? null : num(pump.bondingCurveMarketCap({ mintSupply: curve.tokenTotalSupply, virtualQuoteReserves: curve.virtualQuoteReserves, virtualTokenReserves: curve.virtualTokenReserves }));
    const quoteIsSol = pump.SOL_LIKE_QUOTE_MINTS.some((q) => q.equals(curve.quoteMint));
    let vault = null;
    try { vault = await connection.getBalance(pump.creatorVaultPda(curve.creator)); } catch {}
    pumpInfo = {
      complete: curve.complete, progress: Math.round(progress * 10) / 10,
      marketCapSol: mcLamports === null || !quoteIsSol ? null : mcLamports / LAMPORTS_PER_SOL,
      raisedSol: quoteIsSol ? num(curve.realQuoteReserves) / LAMPORTS_PER_SOL : null, quoteMint: curve.quoteMint.toBase58(),
      creator: curve.creator.toBase58(), creatorVaultSol: vault !== null ? vault / LAMPORTS_PER_SOL : null,
    };
    pumpInfo.curveAccount = getAssociatedTokenAddressSync(mint, pump.bondingCurvePda(mint), true, programId).toBase58();
  }

  const supply = Number(mintInfo.supply) / 10 ** mintInfo.decimals;
  const data = {
    mint: key,
    name: onchainMeta?.name || record?.name || null,
    ticker: onchainMeta?.symbol || record?.ticker || null,
    image: meta?.image || record?.image || dex?.image || null,
    description: meta?.description || record?.description || null,
    target: record?.target || null, targetUrl: record?.targetUrl || null,
    launchedHere: Boolean(record), launchedAt: record?.launchedAt || null,
    supply, decimals: mintInfo.decimals, tokenProgram: programId.equals(TOKEN_2022_PROGRAM_ID) ? 'Token-2022' : 'Token',
    metadataUpdateAuthority: onchainMeta?.updateAuthority || null,
    pump: pumpInfo, market: dex,
    holders: top ? top.map((h) => ({ ...h, isCurve: h.account === pumpInfo?.curveAccount, pct: supply ? Math.round((h.amount / supply) * 10000) / 100 : null })) : null,
    rea: teardown(mintInfo, programId, extTypes, mintInfo, onchainMeta?.updateAuthority || null),
    links: { pump: pumpUrl(key), solscan: `https://solscan.io/token/${key}`, dexscreener: dex?.url || `https://dexscreener.com/solana/${key}` },
    at: Date.now(),
  };
  cache.set(key, { at: Date.now(), data });
  if (cache.size > 500) cache.delete(cache.keys().next().value);
  return data;
}
