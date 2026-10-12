// Coin page: /c/<mint>. Everything comes from /api/coin/<mint> (Solana + pump.fun curve + DexScreener).
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const mint = decodeURIComponent(location.pathname.split('/')[2] || '');

function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.remove('show'), 2200);
}

const usd = (n) => n == null ? '–' : n >= 1e6 ? `$${(n / 1e6).toFixed(2)}M` : n >= 1e3 ? `$${(n / 1e3).toFixed(1)}K` : `$${Number(n).toFixed(n < 1 ? 8 : 2).replace(/0+$/, '').replace(/\.$/, '')}`;
const sol = (n) => n == null ? '–' : `${n >= 100 ? n.toFixed(0) : n.toFixed(3)} SOL`;
const shortKey = (k) => `${k.slice(0, 4)}…${k.slice(-4)}`;
const LABEL = { safe: 'SAFE', caution: 'CAUTION', danger: 'DANGER' };

function stat(label, value, cls = '') { return `<div class="stat ${cls}"><span>${esc(label)}</span><b>${value}</b></div>`; }

function render(d) {
  document.title = `${d.ticker ? '$' + d.ticker : 'Coin'} on CRACKPAD`;
  const m = d.market || {};
  const p = d.pump;
  const progress = p ? p.progress : null;
  const change = m.change24h == null ? '' : `<em class="${m.change24h >= 0 ? 'up' : 'down'}">${m.change24h >= 0 ? '+' : ''}${m.change24h}%</em>`;
  const holders = d.holders ? d.holders.map((h, i) => `
      <tr><td>${i + 1}</td><td><a href="https://solscan.io/account/${esc(h.account)}" target="_blank" rel="noopener">${esc(shortKey(h.account))}</a>${h.isCurve ? ' <span class="tag">pump.fun curve</span>' : ''}</td><td>${h.pct ?? '–'}%</td></tr>`).join('') : '';
  const top10 = d.holders ? d.holders.filter((h) => !h.isCurve).reduce((s, h) => s + (h.pct || 0), 0) : null;
  const rea = d.rea;

  $('coin').innerHTML = `
    <section class="top-row">
      <img src="${esc(d.image || m.image || '/img/pfp-400.png')}" alt="" data-alt="${esc(m.image || '/img/pfp-400.png')}">
      <div>
        <div class="row">${d.launchedHere ? '<span class="tag done">launched on CRACKPAD</span>' : ''}${p ? `<span class="tag">${p.complete ? 'graduated' : 'on the curve'}</span>` : ''}<span class="tag">${esc(d.tokenProgram)}</span></div>
        <h1 class="coin-name">${d.ticker ? '$' + esc(d.ticker) : 'Unknown coin'}</h1>
        <p class="coin-sub">${esc(d.name || '')}</p>
        <button type="button" class="ca" id="copy-ca"><span>CA</span><code>${esc(d.mint)}</code></button>
      </div>
    </section>

    ${d.target ? `<section class="card target"><div class="list-title">The target</div><h2>${esc(d.target)}</h2><p>${esc(d.description || '')}</p>${d.targetUrl ? `<a href="${esc(d.targetUrl)}" target="_blank" rel="noopener nofollow">${esc(d.targetUrl)}</a>` : ''}</section>` : d.description ? `<p class="coin-desc">${esc(d.description)}</p>` : ''}

    <section class="stats">
      ${stat('Market cap', m.marketCap != null ? usd(m.marketCap) : p?.marketCapSol != null ? sol(p.marketCapSol) : '–')}
      ${stat('Price', `${usd(m.priceUsd)} ${change}`)}
      ${stat('Volume 24h', usd(m.volume24h))}
      ${stat('Liquidity', usd(m.liquidityUsd))}
      ${stat('Buys / sells 24h', m.buys24h != null ? `${m.buys24h} / ${m.sells24h}` : '–')}
      ${stat(d.launchedHere ? 'Bounty pot' : 'Creator fees waiting', p?.creatorVaultSol != null ? sol(p.creatorVaultSol) : '–', 'pot')}
    </section>

    ${p && !p.complete ? `<section class="card curve"><div class="list-title">pump.fun bonding curve: ${progress}%</div><div class="bar"><i style="width:${progress}%"></i></div><p>${p.raisedSol != null ? `${sol(p.raisedSol)} in the curve. ` : ''}At 100% it moves to PumpSwap.</p></section>` : ''}

    <section class="card rea">
      <div class="rea-head">
        <div><div class="rea-mark">REA</div><div class="rea-sub">Reverse Engineer Anything: teardown of this coin</div></div>
        <div class="stamp ${esc(rea.verdict)}">${LABEL[rea.verdict]}</div>
      </div>
      <p><b>${esc(rea.summary)}</b></p>
      ${rea.checks.map((c) => `<div class="finding ${c.level === 'bad' ? 'high' : ''}"><span class="sev">${c.level === 'good' ? 'ok' : c.level === 'bad' ? 'risk' : 'note'}</span>${esc(c.title)}${c.detail ? `<span class="ev">${esc(c.detail)}</span>` : ''}</div>`).join('')}
      ${top10 != null ? `<div class="finding ${top10 > 35 ? 'high' : ''}"><span class="sev">${top10 > 35 ? 'risk' : 'ok'}</span>Top holders (outside the curve) own ${top10.toFixed(1)}%</div>` : '<p><em>Holder data needs a keyed RPC.</em></p>'}
      ${p ? `<div class="finding"><span class="sev">note</span>Creator <a href="https://solscan.io/account/${esc(p.creator)}" target="_blank" rel="noopener">${esc(shortKey(p.creator))}</a></div>` : ''}
    </section>

    ${holders ? `<section class="card"><div class="list-title">Top holders</div><table class="holders"><tbody>${holders}</tbody></table></section>` : ''}

    <section class="row links">
      <a class="btn" href="${esc(d.links.pump)}" target="_blank" rel="noopener">Trade on pump.fun</a>
      <a class="btn ghost" href="${esc(d.links.dexscreener)}" target="_blank" rel="noopener">Chart</a>
      <a class="btn ghost" href="${esc(d.links.solscan)}" target="_blank" rel="noopener">Solscan</a>
    </section>
    <p class="note">Updated ${new Date(d.at).toLocaleTimeString()}. Refreshes every 30 seconds.</p>`;

  const img = $('coin').querySelector('.top-row img');
  img.onerror = () => { if (img.src !== new URL(img.dataset.alt, location).href) img.src = img.dataset.alt; else img.src = '/img/pfp-400.png'; };
  $('copy-ca').onclick = () => navigator.clipboard.writeText(d.mint).then(() => toast('CA copied'), () => toast(d.mint));
}

async function load() {
  try {
    const res = await fetch(`/api/coin/${encodeURIComponent(mint)}`);
    const body = await res.json().catch(() => null);
    if (!res.ok) throw new Error(body?.error || 'Could not read that coin.');
    render(body);
  } catch (e) {
    if (!$('coin').querySelector('.top-row')) $('coin').innerHTML = `<p class="empty">${esc(e.message)}</p><p><a class="btn" href="/">Back to CRACKPAD</a></p>`;
  }
}

load();
setInterval(() => { if (!document.hidden) load(); }, 30_000);
