# CRACKPAD

Solana launchpad on pump.fun. Every coin is a "target" (an app, game, drainer kit, closed tool); its pump.fun creator fees go into the bounty pot for cracking it. Site: https://crackpad.fun, X: https://x.com/crackpadfun (hardcoded in server.js and public/*.html). Powered by REA (Reverse Engineer Anything); not affiliated with it.

Launch flow (lib/launch.js): user fills the form -> /api/launch/prepare uploads picture + metadata to pump.fun IPFS and returns a payment tx (user -> launch wallet, LAUNCH_FEE_USD in SOL, memo `crackpad:<draftId>`) -> the user's wallet signs and sends it -> /api/launch/submit checks the payment on-chain, then the launch wallet (LAUNCHER_PRIVATE_KEY) creates the coin with pump-sdk `createV2AndBuyInstructions` plus a tiny dev buy (DEV_BUY_SOL). The launch wallet is the on-chain creator, so creator fees land there. Each launch costs the launch wallet about 0.0085 SOL (account rent + fees), covered by the $2 fee. A paid draft that fails to launch is retried without a second payment.

Coin page (lib/coin.js, public/coin.html, /c/<mint>): live mint data, pump.fun bonding curve, creator fee vault, DexScreener market data, top holders (needs a keyed RPC_URL) and an REA teardown (authorities, Token-2022 extensions).

REA scan: lib/checker (from TEARDOWN) reads uploaded files statically, never runs them.

Run: `npm install && node server.js`. Env vars: see .env.example. In the cloud sandbox add `NODE_USE_ENV_PROXY=1 NODE_EXTRA_CA_CERTS=/root/.ccr/ca-bundle.crt`.

Rules: the site must never read or look AI-made (no "AI" wording, no gradients/glow/emoji). Never send real transactions in tests. Load `@pump-fun/pump-sdk` with createRequire (its ESM build breaks under Node).
