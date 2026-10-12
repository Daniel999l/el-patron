// One shared Solana connection. Set RPC_URL to a keyed RPC (Helius, QuickNode, Triton...) in production:
// the public mainnet RPC rate-limits hard and refuses some calls (largest holders) entirely.
import { Connection, PublicKey } from '@solana/web3.js';

export const RPC_URL = (process.env.RPC_URL || 'https://api.mainnet-beta.solana.com').trim();
export const connection = new Connection(RPC_URL, { commitment: 'confirmed', disableRetryOnRateLimit: true });

export function toKey(s) {
  try { return new PublicKey(String(s || '').trim()); } catch { return null; }
}

export const short = (k) => { const s = String(k); return s.length > 12 ? `${s.slice(0, 4)}…${s.slice(-4)}` : s; };
export const pumpUrl = (mint) => `https://pump.fun/coin/${mint}`;
export const solscan = (k, kind = 'account') => `https://solscan.io/${kind}/${k}`;
