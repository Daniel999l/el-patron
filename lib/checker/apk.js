// Android: binary AndroidManifest.xml (AXML), resources.arsc label lookup, DEX string table.
const ATTR_IDS = { 0x01010003: 'name', 0x01010001: 'label', 0x0101021b: 'versionCode', 0x0101021c: 'versionName', 0x01010006: 'permission' };

function readStringPool(buf, off) {
  const headerSize = buf.readUInt16LE(off + 2);
  const count = buf.readUInt32LE(off + 8);
  const flags = buf.readUInt32LE(off + 16);
  const stringsStart = buf.readUInt32LE(off + 20);
  const utf8 = (flags & 0x100) !== 0;
  const strings = new Array(Math.min(count, 500000));
  const base = off + stringsStart;
  for (let i = 0; i < strings.length; i++) {
    try {
      let p = base + buf.readUInt32LE(off + headerSize + i * 4);
      if (utf8) {
        let n = buf[p++]; if (n & 0x80) p++;            // char length
        let bl = buf[p++]; if (bl & 0x80) bl = ((bl & 0x7f) << 8) | buf[p++];
        strings[i] = buf.toString('utf8', p, p + bl);
      } else {
        let n = buf.readUInt16LE(p); p += 2;
        if (n & 0x8000) { n = ((n & 0x7fff) << 16) | buf.readUInt16LE(p); p += 2; }
        strings[i] = buf.toString('utf16le', p, p + n * 2);
      }
    } catch { strings[i] = ''; }
  }
  return strings;
}

/** Parse binary XML → { package, versionName, versionCode, label, permissions[], elements[{tag,attrs}] } */
export function parseAxml(buf) {
  const out = { package: null, versionName: null, versionCode: null, label: null, permissions: [], elements: [] };
  if (!buf || buf.length < 8 || buf.readUInt16LE(0) !== 0x0003) return out;
  let strings = [], resMap = [];
  let p = 8;
  while (p + 8 <= buf.length && out.elements.length < 20000) {
    const type = buf.readUInt16LE(p), size = buf.readUInt32LE(p + 4);
    if (size < 8) break;
    if (type === 0x0001) strings = readStringPool(buf, p);
    else if (type === 0x0180) { for (let i = p + 8; i + 4 <= p + size; i += 4) resMap.push(buf.readUInt32LE(i)); }
    else if (type === 0x0102) {
      const name = strings[buf.readUInt32LE(p + 20)] || '';
      const aStart = buf.readUInt16LE(p + 24), aSize = buf.readUInt16LE(p + 26) || 20, aCount = buf.readUInt16LE(p + 28);
      const attrs = {};
      for (let a = 0; a < aCount; a++) {
        const q = p + 16 + aStart + a * aSize;
        if (q + 20 > buf.length) break;
        const ni = buf.readUInt32LE(q + 4);
        let an = strings[ni] || '';
        if (resMap[ni] && ATTR_IDS[resMap[ni]]) an = ATTR_IDS[resMap[ni]];
        const raw = buf.readUInt32LE(q + 8), dt = buf[q + 15], data = buf.readUInt32LE(q + 16);
        let v;
        if (raw !== 0xffffffff) v = strings[raw];
        else if (dt === 0x03) v = strings[data];
        else if (dt === 0x01) v = '@0x' + data.toString(16).padStart(8, '0');
        else if (dt === 0x12) v = data !== 0;
        else v = data;
        attrs[an] = v;
      }
      out.elements.push({ tag: name, attrs });
      if (name === 'manifest') {
        out.package = attrs.package ?? null; out.versionName = attrs.versionName ?? null; out.versionCode = attrs.versionCode ?? null;
      } else if ((name === 'uses-permission' || name === 'uses-permission-sdk-23') && attrs.name) out.permissions.push(String(attrs.name));
      else if (name === 'application' && attrs.label != null) out.label = attrs.label;
    }
    p += size;
  }
  return out;
}

/** Resolve a string resource id (e.g. app label) from resources.arsc. Best-effort. */
export function resolveArscString(arsc, resId) {
  try {
    if (!arsc || arsc.readUInt16LE(0) !== 0x0002) return null;
    const typeId = (resId >> 16) & 0xff, entryId = resId & 0xffff;
    let p = arsc.readUInt16LE(2), globalStrings = null;
    while (p + 8 <= arsc.length) {
      const type = arsc.readUInt16LE(p), size = arsc.readUInt32LE(p + 4);
      if (size < 8) break;
      if (type === 0x0001 && !globalStrings) globalStrings = readStringPool(arsc, p);
      else if (type === 0x0200) {
        // package chunk: walk children
        let q = p + arsc.readUInt16LE(p + 2); const end = p + size;
        while (q + 8 <= end) {
          const t = arsc.readUInt16LE(q), s = arsc.readUInt32LE(q + 4);
          if (s < 8) break;
          if (t === 0x0201 && arsc[q + 8] === typeId) {
            const hdr = arsc.readUInt16LE(q + 2), flags = arsc[q + 9];
            const count = arsc.readUInt32LE(q + 12), entriesStart = arsc.readUInt32LE(q + 16);
            let eOff = 0xffffffff;
            if (flags & 0x01) { // sparse
              for (let k = 0; k < count; k++) { const idx = arsc.readUInt16LE(q + hdr + k * 4); if (idx === entryId) { eOff = arsc.readUInt16LE(q + hdr + k * 4 + 2) * 4; break; } }
            } else if (flags & 0x02) { // offset16
              if (entryId < count) { const o = arsc.readUInt16LE(q + hdr + entryId * 2); if (o !== 0xffff) eOff = o * 4; }
            } else if (entryId < count) eOff = arsc.readUInt32LE(q + hdr + entryId * 4);
            if (eOff !== 0xffffffff) {
              const e = q + entriesStart + eOff;
              const eSize = arsc.readUInt16LE(e), eFlags = arsc.readUInt16LE(e + 2);
              if (!(eFlags & 0x0001)) {
                const v = e + eSize; const dt = arsc[v + 3], data = arsc.readUInt32LE(v + 4);
                if (dt === 0x03 && globalStrings && globalStrings[data]) return globalStrings[data];
              }
            }
          }
          q += s;
        }
      }
      p += size;
    }
  } catch {}
  return null;
}

/** Strings from a DEX file's string table. */
export function dexStrings(buf, max = 400000) {
  const out = [];
  try {
    if (buf.toString('latin1', 0, 3) !== 'dex') return out;
    const n = Math.min(buf.readUInt32LE(0x38), max), off = buf.readUInt32LE(0x3c);
    for (let i = 0; i < n; i++) {
      let p = buf.readUInt32LE(off + i * 4);
      while (buf[p] & 0x80) p++; p++;             // skip uleb128 utf16 length
      let e = p; while (e < buf.length && buf[e] !== 0) e++;
      if (e - p >= 3) out.push(buf.toString('utf8', p, e));
    }
  } catch {}
  return out;
}
