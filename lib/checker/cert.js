// Pull X.509 certificates out of DER blobs (PKCS#7 / Authenticode / APK v2 block)
import crypto from 'node:crypto';

function readTL(buf, i) {
  if (i + 2 > buf.length) return null;
  const tag = buf[i]; let len = buf[i + 1]; let h = 2;
  if (len & 0x80) {
    const n = len & 0x7f; if (n === 0 || n > 4 || i + 2 + n > buf.length) return null;
    len = 0; for (let k = 0; k < n; k++) len = len * 256 + buf[i + 2 + k];
    h += n;
  }
  if (i + h + len > buf.length) return null;
  return { tag, hdr: h, len, end: i + h + len };
}

/** Walk DER tree; any SEQUENCE that parses as an X.509 certificate is returned. */
export function findCertificates(der, max = 8) {
  const out = []; let budget = 4000;
  const seen = new Set();
  function walk(start, end, depth) {
    let i = start;
    while (i < end && budget-- > 0 && out.length < max) {
      const tl = readTL(der, i); if (!tl || tl.end > end) return;
      const constructed = tl.tag & 0x20;
      if (tl.tag === 0x30 && tl.len > 200) {
        const slice = der.subarray(i, tl.end);
        const c = tryCert(slice);
        if (c) { const k = c.fingerprint256; if (!seen.has(k)) { seen.add(k); out.push(c); } i = tl.end; continue; }
      }
      if ((constructed || tl.tag === 0x04) && depth < 12 && tl.len > 0) walk(i + tl.hdr, tl.end, depth + 1);
      i = tl.end;
    }
  }
  try { walk(0, der.length, 0); } catch {}
  return out;
}

function tryCert(slice) {
  // cheap pre-check: tbsCertificate is a SEQUENCE starting with [0] version or INTEGER serial
  const inner = readTL(slice, 0); if (!inner) return null;
  const tbs = readTL(slice, inner.hdr); if (!tbs || slice[inner.hdr] !== 0x30) return null;
  const first = slice[inner.hdr + tbs.hdr];
  if (first !== 0xa0 && first !== 0x02) return null;
  try { return new crypto.X509Certificate(slice); } catch { return null; }
}

export function describeCert(c) {
  if (!c) return null;
  return {
    certSha256: c.fingerprint256.replace(/:/g, '').toLowerCase(),
    subject: c.subject.replace(/\n/g, ', '),
    issuer: c.issuer.replace(/\n/g, ', '),
    validFrom: c.validFrom, validTo: c.validTo,
    selfSigned: c.subject === c.issuer,
  };
}

/** APK Signature Scheme v2/v3 block: return certificate DERs. */
export function apkSigningBlockCerts(buf) {
  try {
    // find EOCD -> central directory offset
    let eocd = -1;
    for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) return [];
    const cd = buf.readUInt32LE(eocd + 16);
    if (cd < 32 || buf.toString('latin1', cd - 16, cd) !== 'APK Sig Block 42') return [];
    const size = Number(buf.readBigUInt64LE(cd - 24));
    const start = cd - size - 8;
    if (start < 0) return [];
    let p = start + 8; const end = cd - 24;
    const certs = [];
    while (p + 12 <= end) {
      const len = Number(buf.readBigUInt64LE(p)); const id = buf.readUInt32LE(p + 8);
      const val = buf.subarray(p + 12, p + 8 + len);
      if (id === 0x7109871a || id === 0xf05368c0) certs.push(...scanCerts(val, 4));
      if (certs.length) break;
      p += 8 + len;
    }
    return certs;
  } catch { return []; }
}

/** Scan an arbitrary (non-DER) blob for embedded certificates (30 82 xx xx ...). */
export function scanCerts(val, max = 4) {
  const out = [];
  for (let i = 0; i + 4 < val.length && out.length < max; i++) {
    if (val[i] !== 0x30 || val[i + 1] !== 0x82) continue;
    const len = val.readUInt16BE(i + 2) + 4;
    if (len < 200 || i + len > val.length) continue;
    const c = tryCert(val.subarray(i, i + len));
    if (c) { out.push(c); i += len - 1; }
  }
  return out;
}
