// Windows PE: sections (packer hints), Authenticode cert, version-info strings.
import { findCertificates } from './cert.js';
import { entropy } from './strings.js';

export function isPE(buf) { return buf.length > 0x40 && buf[0] === 0x4d && buf[1] === 0x5a; }

export function parsePE(buf) {
  const out = { ok: false, is64: false, sections: [], certs: [], packer: null };
  try {
    const pe = buf.readUInt32LE(0x3c);
    if (buf.readUInt32LE(pe) !== 0x00004550) return out;
    const nSec = buf.readUInt16LE(pe + 6), optSize = buf.readUInt16LE(pe + 20);
    const opt = pe + 24; const magic = buf.readUInt16LE(opt);
    out.is64 = magic === 0x20b; out.ok = true;
    const ddBase = opt + (out.is64 ? 112 : 96);
    const secOff = buf.readUInt32LE(ddBase + 4 * 8), secSize = buf.readUInt32LE(ddBase + 4 * 8 + 4);
    if (secOff && secSize && secOff + secSize <= buf.length) {
      out.certs = findCertificates(buf.subarray(secOff + 8, secOff + secSize), 6);
    }
    let s = opt + optSize;
    for (let i = 0; i < nSec && i < 96; i++, s += 40) {
      const name = buf.toString('latin1', s, s + 8).replace(/\0.*$/s, '');
      const rawSize = buf.readUInt32LE(s + 16), rawPtr = buf.readUInt32LE(s + 20);
      const data = buf.subarray(rawPtr, Math.min(buf.length, rawPtr + rawSize));
      out.sections.push({ name, size: rawSize, entropy: +entropy(data.subarray(0, 8 * 1024 * 1024)).toFixed(2) });
    }
    const names = out.sections.map(x => x.name.toLowerCase()).join(' ');
    if (/upx\d/.test(names)) out.packer = 'UPX';
    else if (/\.themida|\.winlice/.test(names)) out.packer = 'Themida';
    else if (/\.vmp\d/.test(names)) out.packer = 'VMProtect';
    else if (/\.enigma/.test(names)) out.packer = 'Enigma';
    else if (/\.aspack|\.adata/.test(names)) out.packer = 'ASPack';
  } catch {}
  return out;
}

/** Pull StringFileInfo values out of UTF-16 strings list (key followed by value). */
export function versionInfo(strs) {
  const keys = ['CompanyName', 'ProductName', 'FileDescription', 'OriginalFilename', 'ProductVersion', 'FileVersion', 'InternalName'];
  const info = {};
  for (let i = 0; i < strs.length - 1; i++) {
    if (keys.includes(strs[i]) && !info[strs[i]] && !keys.includes(strs[i + 1])) info[strs[i]] = strs[i + 1].slice(0, 120);
  }
  return info;
}
