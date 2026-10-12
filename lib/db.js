// Storage for reports, check history and launches.
// MONGO_URI (or MONGODB_URI) set  -> MongoDB.   Not set -> plain JSON files in DATA_DIR (for running locally).
import { MongoClient } from 'mongodb';
import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import path from 'node:path';

const URI = (process.env.MONGO_URI || process.env.MONGODB_URI || '').trim();
const DB_NAME = (process.env.MONGO_DB || 'crackpad').trim();
const DIR = path.resolve(process.env.DATA_DIR || './data');

export const usingMongo = () => Boolean(URI);

let client = null, db = null;
const col = (name) => db.collection(name);

// Call once at startup. With a MONGO_URI it fails loudly if the database can't be reached.
export async function initDb() {
  if (!URI) { await mkdir(path.join(DIR, 'reports'), { recursive: true }); return; }
  client = new MongoClient(URI, { serverSelectionTimeoutMS: 15000 });
  await client.connect();
  db = client.db(DB_NAME);
  await Promise.all([
    col('checks').createIndex({ at: -1 }),
    col('launches').createIndex({ draftId: 1 }, { unique: true }),
    col('launches').createIndex({ status: 1, sha: 1, launchedAt: -1 }),
  ]);
}
export async function closeDb() { await client?.close(); client = db = null; }

// ---------- file fallback ----------

let chain = Promise.resolve();
const fileOf = (name) => path.join(DIR, name);
async function readJson(name, fallback) { try { return JSON.parse(await readFile(fileOf(name), 'utf8')); } catch { return fallback; } }
function writeJson(name, mutate) {
  chain = chain.then(async () => {
    await mkdir(DIR, { recursive: true });
    const next = await mutate(await readJson(name, []));
    const tmp = fileOf(name) + `.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(next));
    await rename(tmp, fileOf(name));
  });
  return chain;
}

// ---------- reports: one full result per file hash ----------

export async function saveReport(sha, result) {
  const doc = { ...result, at: new Date().toISOString() };
  if (db) { await col('reports').replaceOne({ _id: sha }, { _id: sha, data: doc }, { upsert: true }); return; }
  await mkdir(path.join(DIR, 'reports'), { recursive: true });
  const tmp = path.join(DIR, 'reports', `${sha}.json.${process.pid}.tmp`);
  await writeFile(tmp, JSON.stringify(doc));
  await rename(tmp, path.join(DIR, 'reports', `${sha}.json`));
}

export async function getReport(sha) {
  if (db) return (await col('reports').findOne({ _id: sha }))?.data || null;
  try { return JSON.parse(await readFile(path.join(DIR, 'reports', `${sha}.json`), 'utf8')); } catch { return null; }
}

// ---------- check history (the recent wall) ----------

export async function addCheck(row) {
  if (db) { await col('checks').insertOne({ ...row }); return; }
  await writeJson('checks.json', (list) => (Array.isArray(list) ? list : []).concat(row).slice(-500));
}

export async function listChecks(limit = 30) {
  const n = Math.max(1, Math.min(500, Number(limit) || 30));
  if (db) return (await col('checks').find({}, { projection: { _id: 0 } }).sort({ at: -1 }).limit(n).toArray());
  await chain;
  const list = await readJson('checks.json', []);
  return (Array.isArray(list) ? list : []).slice(-n).reverse();
}

// ---------- launches ----------

export async function addLaunch(draft) {
  if (db) { await col('launches').insertOne({ ...draft }); return; }
  await writeJson('launches.json', (list) => (Array.isArray(list) ? list : []).concat(draft).slice(-2000));
}

export async function getLaunch(draftId) {
  if (db) return (await col('launches').findOne({ draftId }, { projection: { _id: 0 } })) || null;
  await chain;
  return (await readJson('launches.json', [])).find((x) => x.draftId === draftId) || null;
}

export async function patchLaunch(draftId, patch) {
  if (db) { await col('launches').updateOne({ draftId }, { $set: patch }); return; }
  await writeJson('launches.json', (list) => { const x = list.find((y) => y.draftId === draftId); if (x) Object.assign(x, patch); return list; });
}

export async function liveLaunches(sha) {
  const q = { status: 'live', ...(sha ? { sha } : {}) };
  if (db) return col('launches').find(q, { projection: { _id: 0 } }).sort({ launchedAt: -1 }).limit(200).toArray();
  await chain;
  return (await readJson('launches.json', [])).filter((x) => x.status === 'live' && (!sha || x.sha === sha)).reverse();
}
