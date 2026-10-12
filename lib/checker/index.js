// TEARDOWN App Checker — "Where does your seed phrase / private key go?"
// Static triage only: we unzip, parse manifests and pull strings. Uploaded code is never executed.
import crypto from 'node:crypto';
import path from 'node:path';
import { isZip, unwrapCrx, openZip } from './zip.js';
import { parseAxml, resolveArscString, dexStrings } from './apk.js';
import { isPE, parsePE, versionInfo } from './pe.js';
import { findCertificates, describeCert, apkSigningBlockCerts } from './cert.js';
import { binaryStrings, looksText } from './strings.js';
import { scanText, extractHosts, hostNote, redact } from './rules.js';
import { claimedBrand } from './brands.js';
import { addCheck, listChecks as dbListChecks } from '../db.js';

const TEXT_EXT = /\.(m?js|cjs|jsx|ts|tsx|json|html?|py|pyw|sh|bash|bat|cmd|ps1|psm1|vbs|env|txt|ya?ml|toml|ini|cfg|conf|php|rb|go|rs|java|kt|sol|lua|md)$|(^|\/)(\.env[\w.-]*|Dockerfile|Makefile|Procfile)$/i;
const BIN_EXT = /\.(exe|dll|scr|so|node|bin|dylib|pyd|bundle|hbc)$/i;
const NESTED_EXT = /\.(apk|xapk|aab|zip|crx|xpi|jar)$/i;
const MAX_TEXT = 16 * 1024 * 1024, MAX_BIN = 32 * 1024 * 1024, SCAN_BUDGET = 256 * 1024 * 1024, MAX_FINDINGS = 60;

const APK_PERM_RISK = {
  high: ['READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'RECEIVE_MMS', 'BIND_ACCESSIBILITY_SERVICE', 'SYSTEM_ALERT_WINDOW', 'REQUEST_INSTALL_PACKAGES', 'BIND_DEVICE_ADMIN', 'READ_CALL_LOG', 'BIND_NOTIFICATION_LISTENER_SERVICE', 'MANAGE_EXTERNAL_STORAGE', 'PACKAGE_USAGE_STATS', 'CALL_PHONE', 'PROCESS_OUTGOING_CALLS', 'WRITE_SECURE_SETTINGS', 'REQUEST_DELETE_PACKAGES', 'BIND_VPN_SERVICE'],
  med: ['READ_CONTACTS', 'QUERY_ALL_PACKAGES', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'READ_PHONE_STATE', 'READ_PHONE_NUMBERS', 'WRITE_SETTINGS', 'GET_ACCOUNTS', 'RECEIVE_BOOT_COMPLETED', 'READ_MEDIA_IMAGES', 'DISABLE_KEYGUARD', 'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS', 'FOREGROUND_SERVICE_SPECIAL_USE'],
};
const EXT_PERM_RISK = {
  high: ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*', 'clipboardRead', 'nativeMessaging', 'debugger', 'webRequestBlocking', 'proxy', 'management', 'declarativeNetRequestWithHostAccess', 'privacy', 'desktopCapture'],
  med: ['cookies', 'scripting', 'tabs', 'webRequest', 'history', 'clipboardWrite', 'downloads', 'webNavigation', 'declarativeNetRequest', 'bookmarks', 'topSites', 'identity', 'background'],
};
function permRisk(name, table) {
  const short = String(name).replace(/^android\.permission\.|^com\.android\.\w+\.permission\./, '');
  if (table.high.includes(short) || table.high.includes(name)) return 'high';
  if (table.med.includes(short) || table.med.includes(name)) return 'med';
  if (/^(\*|https?):\/\/\*\.?\//.test(name)) return 'high';
  return 'low';
}

function sha256(b) { return crypto.createHash('sha256').update(b).digest('hex'); }
function extIdFromKey(der) {
  return sha256(der).slice(0, 32).replace(/[0-9a-f]/g, c => String.fromCharCode(97 + parseInt(c, 16)));
}
function pickLeaf(certs) {
  if (!certs.length) return null;
  return certs.find(c => !certs.some(o => o !== c && o.issuer === c.subject && o.subject !== c.subject)) || certs[0];
}

function detectKind(buf, filename) {
  const lower = (filename || '').toLowerCase();
  if (buf.length >= 4 && buf.toString('latin1', 0, 4) === 'Cr24') return 'extension';
  if (isPE(buf)) return 'exe';
  if (isZip(buf)) {
    try {
      const { entries } = openZip(buf);
      const names = entries.map(e => e.name);
      if (names.includes('AndroidManifest.xml') || names.some(n => /^classes\d*\.dex$/.test(n))) return 'apk';
      if (names.includes('manifest.json') || names.filter(n => /^[^/]+\/manifest\.json$/.test(n)).length === 1 && !names.some(n => /(^|\/)package\.json$/.test(n))) {
        return 'extension';
      }
      if (/\.(crx|xpi)$/.test(lower)) return 'extension';
      if (/\.(apk|xapk)$/.test(lower) && names.some(n => /\.apk$/i.test(n))) return 'apk';
    } catch {}
    return 'zip';
  }
  if (/\.(m?js|cjs|jsx|ts|tsx)$/.test(lower)) return 'js';
  if (looksText(buf) && /\b(function|const|let|var|require|import)\b/.test(buf.toString('utf8', 0, 65536))) return 'js';
  return 'other';
}

/** Walk an archive collecting scan units. */
function walkZip(buf, prefix, depth, st) {
  let z; try { z = openZip(buf); } catch { st.notes.add(`${prefix || 'archive'}: could not be opened (corrupt or truncated)`); if (!prefix) st.unreadable = true; return; }
  for (const e of z.entries) {
    if (st.scanned > SCAN_BUDGET) { st.truncated = true; break; }
    const full = prefix + e.name;
    if (e.encrypted) { st.notes.add('encrypted entries skipped'); continue; }
    if (NESTED_EXT.test(e.name) && depth < 2 && e.size <= 150 * 1024 * 1024) {
      const inner = z.read(e, 150 * 1024 * 1024); if (!inner) continue;
      st.nested.push(full);
      const crx = unwrapCrx(inner);
      walkZip(crx ? crx.zip : inner, full + '!/', depth + 1, st);
      continue;
    }
    if (/\.dex$/i.test(e.name)) {
      const d = z.read(e); if (!d) continue; st.scanned += d.length;
      st.units.push({ file: full, type: 'dex', text: dexStrings(d).join('\n') });
    } else if (TEXT_EXT.test(e.name) || /assets\/.*\.(js|html?)$/i.test(e.name)) {
      if (e.size > MAX_TEXT) { st.notes.add('large text files truncated'); }
      const d = z.read(e, MAX_TEXT); if (!d) continue; st.scanned += d.length;
      if (!looksText(d)) { st.units.push({ file: full, type: 'binary', text: binaryStrings(d, { utf16: false }).join('\n') }); continue; }
      st.units.push({ file: full, type: 'source', text: d.toString('utf8') });
      st.texts.set(full, d);
    } else if (BIN_EXT.test(e.name) || /index\.android\.bundle$/.test(e.name)) {
      const d = z.read(e, MAX_BIN); if (!d) continue; st.scanned += d.length;
      if (looksText(d)) { st.units.push({ file: full, type: 'source', text: d.toString('utf8') }); continue; }
      st.units.push({ file: full, type: 'binary', text: binaryStrings(d).join('\n') });
      if (isPE(d)) st.pes.push({ file: full, buf: d });
    }
  }
  if (z.entries.some(e => e.skipped)) st.notes.add('oversized entries skipped (possible zip bomb)');
  st.zips.push({ prefix, z, buf });
}

function readEntry(zipInfo, name) {
  const e = zipInfo.z.entries.find(x => x.name === name);
  return e ? zipInfo.z.read(e) : null;
}

export async function checkFile(buffer, filename = 'upload') {
  if (!Buffer.isBuffer(buffer)) buffer = Buffer.from(buffer);
  const name = path.basename(String(filename || 'upload')).slice(0, 200);
  const kind = detectKind(buffer, name);
  const result = {
    file: { name, kind, size: buffer.length, sha256: sha256(buffer) },
    publisher: null,
    identity: {},
    permissions: [],
    hosts: [],
    findings: [],
    verdict: null,
  };
  const st = { units: [], texts: new Map(), zips: [], nested: [], pes: [], scanned: 0, notes: new Set(), truncated: false };
  const extra = []; // findings from manifest-level checks
  const addF = (severity, id, title, evidence, file) => extra.push({ severity, id, title, evidence: redact(String(evidence)).slice(0, 240), file });

  try {
    if (kind === 'apk') analyzeApk(buffer, result, st, addF);
    else if (kind === 'extension') analyzeExtension(buffer, result, st, addF);
    else if (kind === 'zip') analyzeZip(buffer, result, st, addF);
    else if (kind === 'exe') analyzeExe(buffer, name, result, st, addF);
    else if (kind === 'js') st.units.push({ file: name, type: 'source', text: buffer.toString('utf8') });
    else {
      if (looksText(buffer)) st.units.push({ file: name, type: 'source', text: buffer.toString('utf8', 0, MAX_TEXT) });
      else st.units.push({ file: name, type: 'binary', text: binaryStrings(buffer, { maxBytes: MAX_BIN }).join('\n') });
    }
  } catch (err) {
    st.notes.add('parse error: ' + err.message);
  }

  // Scan all units
  const hostCounts = new Map();
  let all = [...extra];
  for (const u of st.units) {
    if (!u.text) continue;
    try { all.push(...scanText(u, { kind })); } catch {}
    extractHosts(u.text, hostCounts);
  }
  // Dedupe (same id+title+file), then rank by severity, cap.
  const sevRank = { high: 0, med: 1, low: 2 };
  const seen = new Set();
  all = all.filter(f => { const k = f.id + '|' + f.title + '|' + f.file; if (seen.has(k)) return false; seen.add(k); return true; });
  all.sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);
  // Collapse noisy repeats: at most 5 findings per id
  const perId = {};
  result.findings = all.filter(f => (perId[f.id] = (perId[f.id] || 0) + 1) <= 5).slice(0, MAX_FINDINGS);

  result.hosts = [...hostCounts.entries()]
    .map(([host, count]) => {
      const h = { host, count, kind: /^\d{1,3}(\.\d{1,3}){3}$|^\[/.test(host) ? 'ip' : 'domain' };
      const note = hostNote(host); if (note) h.note = note;
      return h;
    })
    .sort((a, b) => (b.note && !/RPC|explorer|market/.test(b.note) ? 1 : 0) - (a.note && !/RPC|explorer|market/.test(a.note) ? 1 : 0) || b.count - a.count)
    .slice(0, 150);

  const notes = [...st.notes];
  if (st.truncated) notes.push('scan budget reached; some files were not scanned');
  if (st.nested.length) notes.push('nested archives scanned: ' + st.nested.slice(0, 5).join(', '));
  if (notes.length) result.notes = notes;
  result.verdict = verdictFor(result);
  if (st.unreadable && result.verdict.level === 'safe') result.verdict = { level: 'caution', score: 10, summary: 'Could not open this file to inspect it (corrupt, truncated or encrypted). No verdict — do not trust it.' };
  else if (!st.units.some(u => u.text) && result.verdict.level === 'safe') result.verdict.summary = 'Nothing readable to analyse in this file. No red flags, but also no evidence it is safe.';

  await recordCheck(result).catch(() => {});
  return result;
}

function analyzeApk(buffer, result, st, addF) {
  walkZip(buffer, '', 0, st);
  const root = st.zips.find(z => z.prefix === '');
  // split APK bundle (.xapk / zip of apks): use the base apk inside
  let apkZip = root;
  if (root && !root.z.entries.some(e => e.name === 'AndroidManifest.xml')) {
    apkZip = st.zips.find(z => z.z.entries.some(e => e.name === 'AndroidManifest.xml')) || root;
  }
  const manifest = parseAxml(readEntry(apkZip, 'AndroidManifest.xml'));
  let label = manifest.label;
  if (typeof label === 'string' && label.startsWith('@0x')) label = resolveArscString(readEntry(apkZip, 'resources.arsc'), parseInt(label.slice(3), 16)) || null;
  result.identity = { packageName: manifest.package || undefined, appName: label || undefined, version: manifest.versionName != null ? String(manifest.versionName) : undefined };
  const seenPerm = new Set();
  result.permissions = manifest.permissions.filter(p => !seenPerm.has(p) && seenPerm.add(p))
    .map(n => ({ name: n, risk: permRisk(n, APK_PERM_RISK) }))
    .sort((a, b) => ({ high: 0, med: 1, low: 2 })[a.risk] - ({ high: 0, med: 1, low: 2 })[b.risk]);

  // Signing certificate: v2/v3 signing block first, then v1 META-INF
  let certs = apkSigningBlockCerts(apkZip === root ? buffer : apkZip.buf);
  if (!certs.length) {
    const sig = apkZip.z.entries.find(e => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name));
    if (sig) certs = findCertificates(apkZip.z.read(sig) || Buffer.alloc(0));
  }
  const leaf = describeCert(pickLeaf(certs));
  if (leaf) result.publisher = { certSha256: leaf.certSha256, subject: leaf.subject, issuer: leaf.issuer };

  const brand = claimedBrand(label, manifest.package);
  if (brand) {
    result.identity.claims = brand.name;
    if (!brand.apk.includes(manifest.package))
      addF('high', 'FAKE_BRAND', `Calls itself ${brand.name} but the package name is not the official one`, `package=${manifest.package} (official: ${brand.apk.join(', ')})`, 'AndroidManifest.xml');
  }
  const els = manifest.elements;
  const acc = els.find(e => e.attrs.permission === 'android.permission.BIND_ACCESSIBILITY_SERVICE');
  if (acc) addF(brand || /wallet|crypto|coin|token/i.test(String(label) + manifest.package) ? 'high' : 'med', 'ACCESSIBILITY_ABUSE',
    'Registers an Accessibility service — can read your screen (incl. seed phrases) and tap for you', `service ${acc.attrs.name || '?'}`, 'AndroidManifest.xml');
  const sms = result.permissions.filter(p => /READ_SMS|RECEIVE_SMS|RECEIVE_MMS/.test(p.name));
  const smsAction = els.find(e => e.tag === 'action' && /SMS_RECEIVED|SMS_DELIVER/.test(String(e.attrs.name)));
  if (sms.length || smsAction) addF('high', 'SMS_READ', 'Can read your SMS — used to steal 2FA / exchange codes', sms.map(p => p.name).join(', ') || smsAction.attrs.name, 'AndroidManifest.xml');
  const overlay = result.permissions.find(p => /SYSTEM_ALERT_WINDOW/.test(p.name));
  if (overlay && acc) addF('med', 'ACCESSIBILITY_ABUSE', 'Accessibility + draw-over-other-apps: classic overlay/phishing combo', overlay.name, 'AndroidManifest.xml');
}

function analyzeExtension(buffer, result, st, addF) {
  const crx = unwrapCrx(buffer);
  walkZip(crx ? crx.zip : buffer, '', 0, st);
  const root = st.zips.find(z => z.prefix === '');
  if (!root) return;
  let base = '';
  if (!root.z.entries.some(e => e.name === 'manifest.json')) {
    const m = root.z.entries.find(e => /^[^/]+\/manifest\.json$/.test(e.name)); if (m) base = m.name.replace('manifest.json', '');
  }
  let manifest = {};
  try { manifest = JSON.parse(stripBom(readEntry(root, base + 'manifest.json')?.toString('utf8') || '{}')); } catch { st.notes.add('manifest.json is not valid JSON'); }
  const msg = (s) => {
    const m = /^__MSG_(\w+)__$/.exec(s || ''); if (!m) return s;
    for (const loc of [manifest.default_locale, 'en', 'en_US'].filter(Boolean)) {
      try {
        const j = JSON.parse(stripBom(readEntry(root, `${base}_locales/${loc}/messages.json`)?.toString('utf8') || '{}'));
        const hit = Object.entries(j).find(([k]) => k.toLowerCase() === m[1].toLowerCase());
        if (hit) return hit[1].message;
      } catch {}
    }
    return s;
  };
  const appName = msg(manifest.name);
  result.identity = { appName: appName || undefined, version: manifest.version || undefined, manifestVersion: manifest.manifest_version };

  let keyDer = crx?.publicKey || null;
  if (!keyDer && manifest.key) { try { keyDer = Buffer.from(manifest.key, 'base64'); } catch {} }
  const extId = keyDer ? extIdFromKey(keyDer) : null;
  if (extId) {
    result.identity.packageName = extId;
    result.publisher = { certSha256: sha256(keyDer), subject: `Chrome extension id ${extId}`, issuer: crx ? `CRX${crx.version} signing key` : 'manifest "key"' };
  }
  const perms = new Set([...(manifest.permissions || []), ...(manifest.host_permissions || []), ...(manifest.optional_permissions || [])].map(String));
  const csMatches = (manifest.content_scripts || []).flatMap(c => c.matches || []);
  for (const m of csMatches) perms.add(m);
  result.permissions = [...perms].map(n => ({ name: n, risk: permRisk(n, EXT_PERM_RISK) }))
    .sort((a, b) => ({ high: 0, med: 1, low: 2 })[a.risk] - ({ high: 0, med: 1, low: 2 })[b.risk]);

  const brand = claimedBrand(appName, manifest.description && msg(manifest.description).slice(0, 80));
  if (brand && claimedBrand(appName)) {
    result.identity.claims = brand.name;
    if (!extId) addF('med', 'FAKE_BRAND', `Calls itself ${brand.name} but is a sideloaded build we can't tie to the official store listing`, `official id(s): ${brand.ext.join(', ') || 'n/a'}`, 'manifest.json');
    else if (!brand.ext.includes(extId)) addF('high', 'FAKE_BRAND', `Calls itself ${brand.name} but its extension id doesn't match the official one`, `id=${extId} (official: ${brand.ext.join(', ') || 'none listed'})`, 'manifest.json');
  }
}

function analyzeZip(buffer, result, st, addF) {
  walkZip(buffer, '', 0, st);
  const root = st.zips.find(z => z.prefix === '');
  const pkgEntry = root?.z.entries.filter(e => /(^|\/)package\.json$/.test(e.name) && !/node_modules\//.test(e.name)).sort((a, b) => a.name.length - b.name.length)[0];
  if (pkgEntry) {
    try {
      const pkg = JSON.parse(stripBom(root.z.read(pkgEntry).toString('utf8')));
      result.identity = { packageName: pkg.name, appName: pkg.description?.slice(0, 80) || pkg.name, version: pkg.version };
      const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
      const odd = deps.filter(d => /^(node-telegram-bot-api|telegraf|discord\.js|nodemailer|clipboardy|javascript-obfuscator|bytenode)$/.test(d));
      if (odd.length) result.identity.notableDeps = odd;
    } catch {}
  }
  const brand = claimedBrand(result.identity.appName, result.identity.packageName);
  if (brand) result.identity.claims = brand.name;
  for (const p of st.pes) analyzePeInner(p.buf, p.file, result, addF, false);
}

function analyzeExe(buffer, name, result, st, addF) {
  const strs = binaryStrings(buffer, { maxBytes: MAX_BIN * 2 });
  st.units.push({ file: name, type: 'binary', text: strs.join('\n') });
  analyzePeInner(buffer, name, result, addF, true, strs);
  // Electron / embedded zip payload (self-extractors): scan an appended archive if present
  const pk = buffer.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  if (pk > 0 && buffer.length - pk > 1024) {
    try { walkZip(buffer.subarray(pk), name + '!/', 1, st); } catch {}
  }
}

function analyzePeInner(buf, file, result, addF, primary, strs) {
  const pe = parsePE(buf);
  if (!pe.ok) return;
  strs = strs || binaryStrings(buf, { maxBytes: MAX_BIN });
  const vi = versionInfo(strs);
  const leaf = describeCert(pickLeaf(pe.certs));
  if (primary) {
    result.identity = { appName: vi.ProductName || vi.FileDescription || undefined, version: vi.ProductVersion || vi.FileVersion || undefined, publisherClaimed: vi.CompanyName || undefined, originalFilename: vi.OriginalFilename || undefined };
    if (leaf) result.publisher = { certSha256: leaf.certSha256, subject: leaf.subject, issuer: leaf.issuer };
    const brand = claimedBrand(vi.ProductName, vi.FileDescription, vi.CompanyName, result.file.name);
    if (brand) {
      result.identity.claims = brand.name;
      const first = brand.name.split(' ')[0].toLowerCase();
      if (!leaf) addF('high', 'FAKE_BRAND', `Looks like ${brand.name} but the program is not code-signed`, `ProductName=${vi.ProductName || '?'} CompanyName=${vi.CompanyName || '?'}`, file);
      else if (!leaf.subject.toLowerCase().includes(first)) addF('high', 'FAKE_BRAND', `Looks like ${brand.name} but is signed by someone else`, `signer: ${leaf.subject.slice(0, 160)}`, file);
    }
  }
  if (pe.packer) addF('med', 'OBFUSCATED', `Packed with ${pe.packer} — hides its real code from inspection`, pe.sections.map(s => `${s.name}(H=${s.entropy})`).join(' '), file);
  else {
    const hot = pe.sections.filter(s => s.entropy > 7.4 && s.size > 64 * 1024);
    if (hot.length && !leaf) addF('low', 'OBFUSCATED', 'High-entropy sections (compressed/encrypted payload) in an unsigned binary', hot.map(s => `${s.name}(H=${s.entropy})`).join(' '), file);
  }
}

function stripBom(s) { return s.replace(/^﻿/, ''); }

const DEST_LABELS = { TELEGRAM_BOT: 'a Telegram bot', DISCORD_WEBHOOK: 'a Discord webhook', RAW_IP_ENDPOINT: 'a bare IP server' };
function verdictFor(r) {
  const w = { high: 35, med: 12, low: 3 };
  const f = r.findings;
  const score = Math.min(100, f.reduce((s, x) => s + w[x.severity], 0));
  const hasHigh = f.some(x => x.severity === 'high'), hasMed = f.some(x => x.severity === 'med');
  const level = hasHigh || score >= 60 ? 'danger' : hasMed || score >= 15 ? 'caution' : 'safe';
  const ids = new Set(f.filter(x => x.severity !== 'low').map(x => x.id));
  const dests = Object.entries(DEST_LABELS).filter(([id]) => f.some(x => x.id === id)).map(([, l]) => l);
  const badHost = r.hosts.find(h => h.note && /tunnel|paste|raw IP/.test(h.note));
  if (badHost && !dests.length) dests.push(badHost.host);
  const what = [ids.has('SEED_EXFIL') && 'seed phrase', ids.has('KEY_EXFIL') && 'private key'].filter(Boolean).join(' / ');
  let summary;
  if (what) summary = `Your ${what} likely leaves the device${dests.length ? ' — destination: ' + dests.join(', ') : ''}. Do not enter a seed or key into this.`;
  else if (ids.has('FAKE_BRAND')) summary = `Impersonates ${r.identity.claims || 'a known wallet'} — not the official build. Treat any seed typed into it as stolen.`;
  else if (ids.has('CLIPBOARD_HIJACK')) summary = 'Swaps crypto addresses in your clipboard — payments would go to the attacker.';
  else if (ids.has('ACCESSIBILITY_ABUSE') || ids.has('SMS_READ')) summary = 'Asks for powers (screen reading / SMS) that let it watch you type your seed and grab 2FA codes.';
  else if (ids.has('EVAL_REMOTE')) summary = 'Downloads and runs code at runtime — what it does with your keys can change at any moment.';
  else if (dests.length) summary = `Contains a hidden data channel (${dests.join(', ')}). No direct seed handling seen, but treat with suspicion.`;
  else if (level === 'caution') summary = 'No direct seed/key exfiltration found, but some red flags — see findings.';
  else summary = 'No seed or key exfiltration patterns found in a static scan. This is not a guarantee — only install wallets from official sources.';
  return { level, score, summary };
}

// ---- history (the recent wall; stored by ../db.js) ----
function recordCheck(r) {
  return addCheck({ sha256: r.file.sha256, name: r.file.name, kind: r.file.kind, verdict: r.verdict, at: new Date().toISOString() });
}

export { dbListChecks as listChecks };
