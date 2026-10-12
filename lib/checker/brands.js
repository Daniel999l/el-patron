// Wallet brands that scam apps / extensions impersonate, with their official identifiers.
// apk = official Android package names; ext = official Chrome Web Store / Edge extension ids.
export const BRANDS = [
  { name: 'MetaMask', re: /\bmeta\s*mask\b/i, apk: ['io.metamask'], ext: ['nkbihfbeogaeaoehlefnkodbefgpgknn', 'ejbalbakoplchlghecdalmeeeajnimhm'] },
  { name: 'Trust Wallet', re: /\btrust\s*wallet\b/i, apk: ['com.wallet.crypto.trustapp'], ext: ['egjidjbpglichdcondbcbdnbeeppgdph'] },
  { name: 'TokenPocket', re: /\btoken\s*pocket\b/i, apk: ['vip.mytokenpocket'], ext: ['mfgccjchihfkkindfppnaooecgfneiii'] },
  { name: 'Phantom', re: /\bphantom\b/i, apk: ['app.phantom'], ext: ['bfnaelmomeimhlpmgjnjophhpkkoljpa'] },
  { name: 'Coinbase Wallet', re: /\bcoinbase\b/i, apk: ['org.toshi', 'com.coinbase.android'], ext: ['hnfanknocfeofbddgcijnmhnfnkdnaad'] },
  { name: 'Exodus', re: /\bexodus\b/i, apk: ['exodusmovement.exodus'], ext: ['aholpfdialjgjfhomihkjbmgjidlcdno'] },
  { name: 'SafePal', re: /\bsafe\s*pal\b/i, apk: ['io.safepal.wallet'], ext: ['lgmpcpglpngdoalbgeoldeajfclnhafa'] },
  { name: 'Bitget Wallet', re: /\b(bitget\s*wallet|bitkeep)\b/i, apk: ['com.bitkeep.wallet'], ext: ['jiidiaalihmmhddjgbnbgdfflelocpak'] },
  { name: 'OKX Wallet', re: /\bokx\b/i, apk: ['com.okinc.okex.gp', 'com.okx.wallet'], ext: ['mcohilncbfahbmgdjkbpemcciiolgcge'] },
  { name: 'Binance', re: /\bbinance\b/i, apk: ['com.binance.dev', 'com.binance.us'], ext: ['fhbohimaelbohpjbbldcngcnapndodjp'] },
  { name: 'Rabby', re: /\brabby\b/i, apk: ['com.debank.rabbymobile'], ext: ['acmacodkjbdgmoleebolmdjonilkdbch'] },
  { name: 'Keplr', re: /\bkeplr\b/i, apk: ['com.chainapsis.keplr'], ext: ['dmkamcknogkgcdfhhbddcghachkejeap'] },
  { name: 'Solflare', re: /\bsolflare\b/i, apk: ['com.solflare.mobile'], ext: ['bhhhlbepdkbapadjdnnojkbgioiodbic'] },
  { name: 'Ledger Live', re: /\bledger\b/i, apk: ['com.ledger.live'], ext: [] },
  { name: 'Atomic Wallet', re: /\batomic\s*wallet\b/i, apk: ['io.atomicwallet'], ext: [] },
  { name: 'Rainbow', re: /\brainbow\s*wallet\b/i, apk: ['me.rainbow'], ext: ['opfgelmcmbiajamepnmloijbpoleiama'] },
  { name: 'Uniswap Wallet', re: /\buniswap\b/i, apk: ['com.uniswap.mobile'], ext: [] },
];

export function claimedBrand(...texts) {
  const hay = texts.filter(Boolean).join(' | ');
  for (const b of BRANDS) if (b.re.test(hay)) return b;
  return null;
}
