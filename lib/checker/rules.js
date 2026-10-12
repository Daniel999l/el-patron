// Static detection rules. Input is text (source code, DEX strings, or `strings` of a binary).
// Nothing here executes the scanned content.

const SEED_RE = /\b(mnemonic\w*|seed[ _-]?phrase|seedPhrase|seed_words|recovery[ _-]?phrase|recoveryPhrase|secret[ _-]?recovery[ _-]?phrase|secretRecoveryPhrase|mnemonicToSeed\w*|validateMnemonic|bip39)\b/i;
const KEY_RE = /\b(private[ _-]?key|privateKey|PRIVATE_KEY|secret[ _-]?key|secretKey|fromSecretKey|exportPrivateKey)\b/i;
const KEY_RE_STRICT = /\b(privateKey|private_key|PRIVATE_KEY|exportPrivateKey|fromSecretKey)\b/;

// strong exfil channels: no legit wallet needs to send data here
const CHANNELS = [
  { re: /api\.telegram\.org\/bot/i, label: 'Telegram Bot API' },
  { re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/, label: 'hardcoded Telegram bot token' },
  { re: /discord(?:app)?\.com\/api\/webhooks\//i, label: 'Discord webhook' },
  { re: /\bwebhook\.site\b|\brequestbin\b|\bpipedream\.net\b|\bhookbin\.com\b|\bbeeceptor\.com\b|\bngrok(?:-free)?\.(?:io|app)\b|\btrycloudflare\.com\b/i, label: 'request-capture / tunnel service' },
  { re: /pastebin\.com\/api|\bhastebin\b|\bpaste\.ee\b|\bjsonbin\.io\b/i, label: 'paste service' },
  { re: /\bhttps?:\/\/(?!(?:10|127|0)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/, label: 'raw IP address' },
  { re: /\bsmtplib\b|\bnodemailer\b|\bsmtp\.(gmail|mail|yandex|office365)\b/i, label: 'email (SMTP)' },
];

// network call whose argument list contains a secret (≈ "the seed is the payload")
const SINK = String.raw`(?:fetch|axios(?:\.\w+)?|\$\.(?:ajax|post|get)|sendBeacon|\.send|\.post|\.put|requests\.(?:post|get|put)|httpx\.\w+|urlopen|http\.request|https\.request|sendMessage|\.emit|\.write)`;
const SEED_ARG_RE = new RegExp(SINK + String.raw`\s*\([^;]{0,400}?\b(mnemonic\w*|seed[_ ]?phrase|seedPhrase|recovery[_ ]?phrase|recoveryPhrase|secretRecoveryPhrase|seed_words)\b`, 'i');
const KEY_ARG_RE = new RegExp(SINK + String.raw`\s*\([^;]{0,400}?\b(private[_ ]?key|privateKey|PRIVATE_KEY|secretKey|secret_key)\b`, 'i');
// form fields named like seed inputs being serialized and shipped
const SEED_FORM_RE = /(phrase|mnemonic|seed)[^;]{0,80}(\.value|FormData|serialize|JSON\.stringify)[^;]{0,200}(fetch|ajax|post|send)\s*\(/i;

const WALLET_VAULTS = [
  /nkbihfbeogaeaoehlefnkodbefgpgknn/, /bfnaelmomeimhlpmgjnjophhpkkoljpa/, /egjidjbpglichdcondbcbdnbeeppgdph/, /hnfanknocfeofbddgcijnmhnfnkdnaad/,
  /exodus[\\/]+exodus\.wallet/i, /Electrum[\\/]+wallets/i, /atomic[\\/]+Local Storage/i, /\bwallet\.dat\b/i, /Ethereum[\\/]+keystore/i,
  /Local Extension Settings/i, /\bjaxx\b/i, /Coinomi[\\/]+wallets/i, /Guarda[\\/]+Local Storage/i, /\.config[\\/]+solana[\\/]+id\.json/i,
];

const CLIP_READ = /navigator\.clipboard\.readText|clipboard\.readText|readText\(\)|GetClipboardData|getPrimaryClip|pyperclip\.paste|clipboardy\.read|Clipboard\.GetText|clipboard\.read\(/;
const CLIP_WRITE = /clipboard\.writeText|SetClipboardData|setPrimaryClip|pyperclip\.copy|clipboardy\.write|Clipboard\.SetText|execCommand\(\s*['"]copy/;
const ADDR_PATTERN = /0x\[a-fA-F0-9\]\{40\}|0x\[0-9a-fA-F\]\{40\}|\{25,3[49]\}|\{26,3[3-5]\}|\{32,44\}|\{39,59\}|\^T\[|bc1\[|\^\(bc1|\[13\]\[a-km-zA-HJ-NP-Z1-9\]/;

const OBF_HEX_ID = /\b_0x[a-f0-9]{4,6}\b/g;
const PACKER_JS = /eval\(function\(p,a,c,k,e,[rd]\)/;
const PY_OBF = /exec\(\s*(?:base64\.b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|codecs\.decode)|__pyarmor__|pyarmor_runtime/;

const EVAL_REMOTE = [
  { re: /\.then\(\s*eval\s*\)|\.then\(\s*\w+\s*=>\s*eval\(|eval\(\s*await\s+\(?\s*(?:await\s+)?(?:fetch|axios)|new Function\(\s*await|new Function\([^)]{0,80}(?:\.data|responseText|\.text\(\))/, sev: 'high', what: 'evaluates code downloaded at runtime' },
  { re: /eval\(\s*(?:\w+\.)?(?:responseText|response\.data|res\.data|body)\s*\)/, sev: 'high', what: 'evals a network response' },
  { re: /exec\(\s*(?:requests|urllib\.request|httpx)\.(?:get|urlopen)\(/, sev: 'high', what: 'Python exec() of a downloaded payload' },
  { re: /(?:exec|execSync|spawn)\(\s*[`'"][^`'"]{0,200}(?:curl|wget|powershell|Invoke-WebRequest|iwr |certutil)/i, sev: 'high', what: 'shells out to download/run something' },
  { re: /\b(?:IEX|Invoke-Expression)\b[^\n]{0,120}(?:DownloadString|Net\.WebClient|iwr|Invoke-WebRequest)|DownloadString\(|powershell(?:\.exe)?\s+[^\n]{0,40}-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}/i, sev: 'high', what: 'PowerShell download cradle' },
  { re: /\bURLDownloadToFile[AW]?\b/, sev: 'med', what: 'downloads files (URLDownloadToFile)' },
  { re: /Ldalvik\/system\/(?:DexClassLoader|InMemoryDexClassLoader)|dalvik\.system\.(?:DexClassLoader|InMemoryDexClassLoader)/, sev: 'med', what: 'loads extra code at runtime (DexClassLoader)' },
  { re: /"(?:pre|post)?install"\s*:\s*"[^"]*(?:curl|wget|node\s+-e|powershell|bash\s+-c|\.sh\b)/, sev: 'high', what: 'npm install hook runs a command' },
];

const NOISE_HOSTS = /(^|\.)(schemas\.android\.com|w3\.org|xmlpull\.org|apache\.org|ns\.adobe\.com|schemas\.microsoft\.com|schemas\.openxmlformats\.org|purl\.org|xml\.org|example\.(com|org)|localhost|json-schema\.org|mozilla\.org|reactjs\.org|react\.dev|github\.com\/facebook|digicert\.com|verisign\.com|sectigo\.com|globalsign\.com|usertrust\.com|comodoca\.com|symcb\.com|symcd\.com|thawte\.com|entrust\.net|microsoft\.com\/pki|ocsp\.\w+\.\w+|crl\.\w+\.\w+)$/i;

const URL_RE = /\b(?:https?|wss?):\/\/(\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+)(?::\d{2,5})?/gi;

export function hostNote(host) {
  if (/^(10|127|0)\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(host)) return 'private/local IP';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return 'raw IP — no domain name';
  if (/api\.telegram\.org$/i.test(host)) return 'Telegram Bot API';
  if (/discord(app)?\.com$/i.test(host)) return 'Discord';
  if (/webhook\.site|requestbin|pipedream|hookbin|beeceptor|ngrok|trycloudflare/i.test(host)) return 'request-capture / tunnel service';
  if (/pastebin|hastebin|paste\.ee|jsonbin/i.test(host)) return 'paste service';
  if (/infura\.io|alchemy(api)?\.(io|com)|quiknode|quicknode|ankr\.com|bsc-dataseed|binance\.org|publicnode|llamarpc|helius|solana\.com|mainnet-beta|blastapi|chainstack|drpc\.org|getblock\.io/i.test(host)) return 'blockchain RPC';
  if (/etherscan|bscscan|solscan|polygonscan|arbiscan|basescan/i.test(host)) return 'block explorer';
  if (/coingecko|coinmarketcap|dexscreener|birdeye|jup\.ag|1inch|0x\.org|pancakeswap|uniswap|raydium/i.test(host)) return 'market data / DEX';
  return undefined;
}

export function extractHosts(text, counts) {
  URL_RE.lastIndex = 0; let m, n = 0;
  while ((m = URL_RE.exec(text)) && n++ < 50000) {
    const host = m[1].toLowerCase();
    if (NOISE_HOSTS.test(host) || /\.(png|jpg|svg|gif|js|css|html?)$/.test(host)) continue;
    counts.set(host, (counts.get(host) || 0) + 1);
  }
}

function snippet(text, idx, len = 0, pad = 70) {
  const s = Math.max(0, idx - pad), e = Math.min(text.length, idx + len + pad);
  return redact(text.slice(s, e).replace(/\s+/g, ' ').trim()).slice(0, 240);
}
export function redact(s) {
  return s
    .replace(/\b(\d{8,10}):AA([A-Za-z0-9_-]{4})[A-Za-z0-9_-]{29}\b/g, '$1:AA$2…[redacted]')
    .replace(/(discord(?:app)?\.com\/api\/webhooks\/\d+\/)([\w-]{6})[\w-]+/gi, '$1$2…[redacted]')
    .replace(/\b(0x)?([a-fA-F0-9]{6})[a-fA-F0-9]{52}([a-fA-F0-9]{6})\b/g, '$1$2…$3');
}
function firstMatch(re, text) { const m = re.exec(text); return m ? { idx: m.index, len: m[0].length, m } : null; }

/**
 * Scan one unit of text.
 * @param {{file:string, text:string, type:'source'|'dex'|'binary'}} unit
 * @param {{kind:string}} ctx  (file kind of the upload)
 */
export function scanText(unit, ctx) {
  const { file, text, type } = unit;
  const findings = [];
  const add = (severity, id, title, evidence) => findings.push({ severity, id, title, evidence, file });
  const isSrc = type === 'source';
  const shipsAsApp = ctx.kind === 'apk' || ctx.kind === 'extension' || ctx.kind === 'exe';

  const seed = firstMatch(SEED_RE, text);
  // In DEX / binary strings, Java's PrivateKey/SecretKey classes are everywhere: be case-sensitive there.
  const key = firstMatch(isSrc ? KEY_RE : KEY_RE_STRICT, text);
  const channels = [];
  for (const c of CHANNELS) {
    if (!isSrc && c.label === 'raw IP address') continue; // raw IPs in compiled code handled by RAW_IP_ENDPOINT
    const h = firstMatch(c.re, text); if (h) channels.push({ ...c, ...h });
  }

  // --- Telegram / Discord
  const tgTok = firstMatch(/\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/, text);
  const tgApi = firstMatch(/api\.telegram\.org\/bot/i, text);
  if (tgTok || tgApi) {
    const hit = tgTok || tgApi;
    const withSecret = !!(seed || key);
    const sev = tgTok ? (shipsAsApp || withSecret ? 'high' : 'med') : (withSecret && isSrc ? 'med' : 'low');
    add(sev, 'TELEGRAM_BOT', tgTok ? 'Hardcoded Telegram bot token — data can be pushed to a private Telegram chat' : 'Talks to the Telegram Bot API', snippet(text, hit.idx, hit.len));
  }
  const dw = firstMatch(/discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/i, text);
  if (dw) add(shipsAsApp || seed || key ? 'high' : 'med', 'DISCORD_WEBHOOK', 'Hardcoded Discord webhook — anything posted lands in someone\'s Discord channel', snippet(text, dw.idx, dw.len));

  // --- raw IP endpoints
  const ip = firstMatch(/\b(?:https?|wss?):\/\/(?!(?:10|127|0)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?[^\s'"`)]{0,60}/i, text);
  if (ip) add(seed || key ? 'high' : 'med', 'RAW_IP_ENDPOINT', `Sends traffic to a bare IP address (${ip.m[1]}) instead of a domain`, snippet(text, ip.idx, ip.len));

  // --- seed / key exfil
  const exfilVia = channels.map(c => c.label);
  if (isSrc) {
    const sa = firstMatch(SEED_ARG_RE, text) || firstMatch(SEED_FORM_RE, text);
    if (sa) add('high', 'SEED_EXFIL', 'Seed phrase is passed straight into a network call', snippet(text, sa.idx, sa.len, 40));
    const ka = firstMatch(KEY_ARG_RE, text);
    if (ka && !/(signTransaction|sendTransaction|Wallet\(|Keypair|new ethers|web3)/.test(ka.m[0])) add('high', 'KEY_EXFIL', 'Private key is passed straight into a network call', snippet(text, ka.idx, ka.len, 40));
  }
  if (seed && channels.length && !findings.some(f => f.id === 'SEED_EXFIL'))
    add('high', 'SEED_EXFIL', `Handles seed phrases AND contains an exfil channel (${exfilVia.join(', ')}) in the same file`, snippet(text, seed.idx, seed.len));
  if (key && channels.length && !findings.some(f => f.id === 'KEY_EXFIL'))
    add(shipsAsApp || isSrc ? 'high' : 'med', 'KEY_EXFIL', `Handles private keys AND contains an exfil channel (${exfilVia.join(', ')}) in the same file`, snippet(text, key.idx, key.len));
  const vaultHits = WALLET_VAULTS.map(r => firstMatch(r, text)).filter(Boolean);
  if (vaultHits.length >= 2 && ctx.kind !== 'extension')
    add('high', 'SEED_EXFIL', `Looks for other wallets' vault files on disk (${vaultHits.length} wallet paths/ids) — typical stealer behaviour`, vaultHits.slice(0, 3).map(h => redact(h.m[0])).join(' | '));

  // --- clipboard hijack
  const cr = firstMatch(CLIP_READ, text), cw = firstMatch(CLIP_WRITE, text);
  if (cr && cw) {
    const ap = firstMatch(ADDR_PATTERN, text);
    if (ap) add('high', 'CLIPBOARD_HIJACK', 'Reads & rewrites the clipboard and matches crypto-address patterns (address swapper)', snippet(text, ap.idx, ap.len));
    else if (type === 'binary') add('low', 'CLIPBOARD_HIJACK', 'Reads and writes the clipboard', `${cr.m[0]} / ${cw.m[0]}`);
  }

  // --- obfuscation
  if (isSrc) {
    const hex = (text.match(OBF_HEX_ID) || []).length;
    if (hex >= 150) add('med', 'OBFUSCATED', `Heavily obfuscated JavaScript (${hex} _0x… identifiers, javascript-obfuscator style)`, snippet(text, text.search(OBF_HEX_ID), 20));
    const pk = firstMatch(PACKER_JS, text); if (pk) add('med', 'OBFUSCATED', 'Packed with an eval() packer (p,a,c,k,e,d)', snippet(text, pk.idx, pk.len));
    const py = firstMatch(PY_OBF, text); if (py) add('med', 'OBFUSCATED', 'Python code that decodes and exec()s a hidden payload', snippet(text, py.idx, py.len));
    const blob = firstMatch(/['"`][A-Za-z0-9+/]{4000,}={0,2}['"`]/, text);
    if (blob && /\b(eval|Function|exec|atob|Buffer\.from|b64decode)\b/.test(text)) add('low', 'OBFUSCATED', `Large encoded blob (${blob.len} chars) next to a decoder`, snippet(text, blob.idx, 60, 30));
  }

  // --- remote code
  for (const r of EVAL_REMOTE) {
    if (r.re.source.includes('dalvik') && type !== 'dex') continue;
    const h = firstMatch(r.re, text);
    if (h) add(r.sev, 'EVAL_REMOTE', 'Runs code it fetches at runtime: ' + r.what, snippet(text, h.idx, h.len));
  }
  return findings;
}
