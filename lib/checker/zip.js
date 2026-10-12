// Minimal, defensive ZIP reader (no deps). Reads the central directory and
// inflates entries on demand with hard size caps (zip-bomb safe).
import zlib from 'node:zlib';

export const LIMITS = {
  maxEntries: 20000,
  maxEntryBytes: 48 * 1024 * 1024,   // per inflated entry
  maxTotalBytes: 256 * 1024 * 1024,  // across one archive
};

export function isZip(buf) {
  return buf.length >= 4 && buf.readUInt32LE(0) === 0x04034b50;
}

/** If buf is a CRX (Cr24 v2/v3), return { zip, header } else null. */
export function unwrapCrx(buf) {
  if (buf.length < 16 || buf.toString('latin1', 0, 4) !== 'Cr24') return null;
  const version = buf.readUInt32LE(4);
  if (version === 2) {
    const keyLen = buf.readUInt32LE(8), sigLen = buf.readUInt32LE(12);
    const start = 16 + keyLen + sigLen;
    return { version, publicKey: buf.subarray(16, 16 + keyLen), zip: buf.subarray(start) };
  }
  if (version === 3) {
    const hdrLen = buf.readUInt32LE(8);
    const header = buf.subarray(12, 12 + hdrLen);
    return { version, header, publicKey: crx3FirstKey(header), zip: buf.subarray(12 + hdrLen) };
  }
  return null;
}

// CrxFileHeader protobuf: field 2 = sha256_with_rsa (AsymmetricKeyProof{1:public_key,2:signature}),
// field 3 = sha256_with_ecdsa. Return the first public key we see.
function crx3FirstKey(h) {
  try {
    let i = 0;
    while (i < h.length) {
      const [tag, n1] = varint(h, i); i = n1;
      const field = tag >> 3, wt = tag & 7;
      if (wt === 2) {
        const [len, n2] = varint(h, i); i = n2;
        const body = h.subarray(i, i + len); i += len;
        if (field === 2 || field === 3) {
          let j = 0;
          while (j < body.length) {
            const [t2, m1] = varint(body, j); j = m1;
            if ((t2 & 7) !== 2) break;
            const [l2, m2] = varint(body, j); j = m2;
            if ((t2 >> 3) === 1) return body.subarray(j, j + l2);
            j += l2;
          }
        }
      } else if (wt === 0) { i = varint(h, i)[1]; }
      else break;
    }
  } catch {}
  return null;
}
function varint(b, i) {
  let r = 0, s = 0, c;
  do { c = b[i++]; r += (c & 0x7f) * 2 ** s; s += 7; } while (c & 0x80 && s < 50);
  return [r, i];
}

/** Parse central directory. Returns { entries:[{name,method,compSize,size,offset}], read(entry)->Buffer|null } */
export function openZip(buf) {
  let eocd = -1;
  const stop = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= stop; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not a zip (no end-of-central-directory)');
  let count = buf.readUInt16LE(eocd + 10);
  let cdOff = buf.readUInt32LE(eocd + 16);
  // Zip64 locator
  if ((cdOff === 0xffffffff || count === 0xffff) && eocd >= 20 && buf.readUInt32LE(eocd - 20) === 0x07064b50) {
    const z64 = Number(buf.readBigUInt64LE(eocd - 12));
    if (z64 + 56 <= buf.length && buf.readUInt32LE(z64) === 0x06064b50) {
      count = Number(buf.readBigUInt64LE(z64 + 32));
      cdOff = Number(buf.readBigUInt64LE(z64 + 48));
    }
  }
  const entries = [];
  let p = cdOff;
  for (let n = 0; n < count && n < LIMITS.maxEntries; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) break;
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    let compSize = buf.readUInt32LE(p + 20);
    let size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28), extraLen = buf.readUInt16LE(p + 30), commentLen = buf.readUInt16LE(p + 32);
    let offset = buf.readUInt32LE(p + 42);
    const name = buf.toString(flags & 0x800 ? 'utf8' : 'latin1', p + 46, p + 46 + nameLen);
    // zip64 extra field
    let e = p + 46 + nameLen; const eEnd = e + extraLen;
    while (e + 4 <= eEnd) {
      const id = buf.readUInt16LE(e), len = buf.readUInt16LE(e + 2);
      if (id === 0x0001) {
        let q = e + 4;
        if (size === 0xffffffff && q + 8 <= e + 4 + len) { size = Number(buf.readBigUInt64LE(q)); q += 8; }
        if (compSize === 0xffffffff && q + 8 <= e + 4 + len) { compSize = Number(buf.readBigUInt64LE(q)); q += 8; }
        if (offset === 0xffffffff && q + 8 <= e + 4 + len) { offset = Number(buf.readBigUInt64LE(q)); }
      }
      e += 4 + len;
    }
    if (!name.endsWith('/')) entries.push({ name, method, compSize, size, offset, encrypted: !!(flags & 1) });
    p = eEnd + commentLen;
  }
  let total = 0;
  function read(entry, cap = LIMITS.maxEntryBytes) {
    try {
      if (entry.encrypted) return null;
      const o = entry.offset;
      if (o + 30 > buf.length || buf.readUInt32LE(o) !== 0x04034b50) return null;
      const start = o + 30 + buf.readUInt16LE(o + 26) + buf.readUInt16LE(o + 28);
      const comp = buf.subarray(start, Math.min(buf.length, start + entry.compSize));
      const budget = Math.min(cap, LIMITS.maxTotalBytes - total);
      if (budget <= 0) return null;
      let out;
      if (entry.method === 0) out = comp.subarray(0, budget);
      else if (entry.method === 8) {
        try { out = zlib.inflateRawSync(comp, { maxOutputLength: budget }); }
        catch (err) {
          // Over budget (likely a bomb or huge asset): skip it.
          if (/larger than|too large|ERR_BUFFER_TOO_LARGE/i.test(err.code + ' ' + err.message)) { entry.skipped = 'too-large'; return null; }
          else return null;
        }
      } else return null;
      total += out.length;
      return out;
    } catch { return null; }
  }
  return { entries, read };
}

