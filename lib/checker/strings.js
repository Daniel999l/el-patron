// Printable-string extraction from binaries (ASCII + UTF-16LE), like `strings`.
export function binaryStrings(buf, { min = 5, maxBytes = 64 * 1024 * 1024, utf16 = true } = {}) {
  const out = []; const end = Math.min(buf.length, maxBytes);
  let s = -1;
  for (let i = 0; i <= end; i++) {
    const c = i < end ? buf[i] : 0;
    const ok = c >= 0x20 && c < 0x7f || c === 0x09;
    if (ok) { if (s < 0) s = i; }
    else { if (s >= 0 && i - s >= min) out.push(buf.toString('latin1', s, i)); s = -1; }
  }
  if (utf16) {
    for (const align of [0, 1]) {
      s = -1;
      for (let i = align; i + 1 <= end; i += 2) {
        const lo = i + 1 < end ? buf[i] : 0, hi = i + 1 < end ? buf[i + 1] : 1;
        const ok = hi === 0 && (lo >= 0x20 && lo < 0x7f);
        if (ok) { if (s < 0) s = i; }
        else { if (s >= 0 && (i - s) / 2 >= min) out.push(buf.toString('utf16le', s, i)); s = -1; }
      }
    }
  }
  return out;
}

export function entropy(buf) {
  if (!buf.length) return 0;
  const f = new Uint32Array(256); for (const b of buf) f[b]++;
  let h = 0; for (const n of f) if (n) { const p = n / buf.length; h -= p * Math.log2(p); }
  return h;
}

export function looksText(buf) {
  const n = Math.min(buf.length, 4096); if (!n) return true;
  let bad = 0; for (let i = 0; i < n; i++) { const c = buf[i]; if (c === 0) return false; if (c < 9 || (c > 13 && c < 32)) bad++; }
  return bad / n < 0.02;
}
