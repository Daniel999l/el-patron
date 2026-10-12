import express from 'express';
import multer from 'multer';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkFile } from './lib/checker/index.js';
import { prepareLaunch, submitLaunch, boardCoins, launchFeeLamports, launcherAddress, UserError } from './lib/launch.js';
import { initDb, saveReport, getReport, usingMongo } from './lib/db.js';
import { pumpUrl } from './lib/solana.js';
import { coinData, CoinError } from './lib/coin.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const CA = (process.env.TOKEN_CA || '').trim() || null;

export const SITE_URL = 'https://crackpad.fun';
export const X_URL = 'https://x.com/crackpadfun';

await initDb();
console.log(usingMongo() ? 'storage: MongoDB' : 'storage: local files (set MONGO_URI to use MongoDB)');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '256kb' }));
const imageUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024, files: 1 } });
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 150 * 1024 * 1024, files: 1 } });

// Small in-memory rate limit: 12 per minute per IP and bucket.
const hits = new Map();
function limited(key, max = 12) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < 60_000);
  arr.push(now);
  hits.set(key, arr);
  if (hits.size > 5000) hits.delete(hits.keys().next().value);
  return arr.length > max;
}

const userError = (res, e) => {
  if (e instanceof UserError) return res.status(e.status).json({ error: e.message });
  console.error(e);
  return res.status(500).json({ error: 'Something went wrong. Try again.' });
};

app.get('/health', (_req, res) => res.json({ ok: true }));

app.get('/api/config', async (_req, res) => {
  const fee = await launchFeeLamports().catch(() => null);
  res.json({
    launchFeeUsd: Number(process.env.LAUNCH_FEE_USD) || 2,
    launchFeeSol: fee ? fee / 1e9 : null,
    launcher: launcherAddress(),
    name: process.env.TOKEN_NAME || 'CRACKPAD',
    ticker: process.env.TOKEN_TICKER || 'CRACK',
    tokenCa: CA,
    buyUrl: CA ? pumpUrl(CA) : null,
    x: X_URL,
    tg: process.env.TG_URL || null,
  });
});

// ---------- free file scan ----------

app.post('/api/check', (req, res) => {
  if (limited('check:' + req.ip)) return res.status(429).json({ error: 'Too many uploads. Try again in a minute.' });
  upload.single('file')(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'File is over 150MB.' : 'Upload failed.' });
    if (!req.file) return res.status(400).json({ error: 'No file received.' });
    try {
      const result = await checkFile(req.file.buffer, req.file.originalname);
      await saveReport(result.file.sha256, result);
      res.json(result);
    } catch (e) {
      console.error('check failed', e);
      res.status(500).json({ error: 'Could not read this file.' });
    }
  });
});

app.get('/api/report/:sha', async (req, res) => {
  if (!/^[a-f0-9]{64}$/.test(req.params.sha)) return res.status(400).json({ error: 'Bad id.' });
  const report = await getReport(req.params.sha).catch(() => null);
  if (!report) return res.status(404).json({ error: 'Report not found.' });
  res.json(report);
});

// ---------- launch: prepare -> wallet signs -> submit ----------

app.post('/api/launch/prepare', (req, res) => {
  if (limited('launch:' + req.ip)) return res.status(429).json({ error: 'Too many tries. Wait a minute.' });
  imageUpload.single('image')(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'The picture must be under 2 MB.' : 'Upload failed.' });
    try {
      res.json(await prepareLaunch({ body: req.body || {}, image: req.file?.buffer, siteUrl: SITE_URL, x: X_URL }));
    } catch (e) { userError(res, e); }
  });
});

app.post('/api/launch/submit', async (req, res) => {
  if (limited('submit:' + req.ip)) return res.status(429).json({ error: 'Too many tries. Wait a minute.' });
  try { res.json(await submitLaunch(req.body || {})); } catch (e) { userError(res, e); }
});

app.get('/api/coins', async (_req, res) => {
  res.json(await boardCoins().catch(() => []));
});

app.get('/api/coin/:mint', async (req, res) => {
  if (limited('coin:' + req.ip, 40)) return res.status(429).json({ error: 'Too many lookups. Wait a minute.' });
  try { res.json(await coinData(req.params.mint)); }
  catch (e) {
    if (e instanceof CoinError) return res.status(e.status).json({ error: e.message });
    console.error('coin', e);
    res.status(500).json({ error: 'Could not read that coin. Try again.' });
  }
});

app.get('/c/:mint', (_req, res) => res.sendFile(path.join(ROOT, 'public', 'coin.html')));

app.get('/vendor/web3.js', (_req, res) => {
  res.type('application/javascript').sendFile(path.join(ROOT, 'node_modules/@solana/web3.js/lib/index.iife.min.js'));
});
app.use(express.static(path.join(ROOT, 'public'), { extensions: ['html'] }));

app.listen(PORT, () => console.log(`CRACKPAD on :${PORT}`));
