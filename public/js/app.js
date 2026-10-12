// CRACKPAD page: board, launch (wallet signs, server co-signs with the new mint and sends), free file scan.
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.remove('show'), 2600);
}

async function api(url, opts) {
  const res = await fetch(url, opts);
  let body = null;
  try { body = await res.json(); } catch {}
  if (!res.ok) throw new Error(body?.error || `Request failed (${res.status})`);
  return body;
}

// ---------- config: CA pill + buy button ----------

async function loadConfig() {
  const cfg = await api('/api/config').catch(() => null);
  if (cfg?.launchFeeSol) $('fee').textContent = `about $${cfg.launchFeeUsd} (${cfg.launchFeeSol} SOL)`;
  if (!cfg?.tokenCa) return;
  $('ca-text').textContent = cfg.tokenCa;
  $('ca').hidden = false;
  $('buy').href = cfg.buyUrl;
  $('buy').hidden = false;
  $('ca-copy').onclick = () => navigator.clipboard.writeText(cfg.tokenCa).then(() => toast('CA copied'), () => toast(cfg.tokenCa));
}

// ---------- board ----------

const ago = (t) => {
  const s = Math.max(1, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
};

async function loadBoard() {
  const list = await api('/api/coins').catch(() => []);
  if (!list.length) return;
  $('board-list').innerHTML = list.map((c) => `
    <a class="coin" href="/c/${esc(c.mint)}">
      <img src="${esc(c.image || '/img/pfp-400.png')}" alt="" loading="lazy">
      <div>
        <h3>$${esc(c.ticker)} <span class="t">${esc(c.name)}</span></h3>
        <div><span class="tag ${c.cracked ? 'done' : ''}">${c.cracked ? 'cracked' : 'open'}</span><b>${esc(c.target)}</b></div>
        <div class="meta">${esc(c.description).slice(0, 110)}</div>
        <div class="meta">${c.launchedAt ? ago(c.launchedAt) : ''} · ${esc(c.mint.slice(0, 4))}…${esc(c.mint.slice(-4))}</div>
      </div>
    </a>`).join('');
}

// ---------- wallet ----------

let wallet = null, owner = null;

function provider() {
  return window.phantom?.solana || window.solflare || window.backpack || window.solana || null;
}

async function connect() {
  const p = provider();
  if (!p) {
    toast('No Solana wallet found. Install Phantom or Solflare, or open this site in your wallet app.');
    return null;
  }
  try {
    const res = await p.connect();
    const key = res?.publicKey || p.publicKey;
    wallet = p;
    owner = key.toString();
    $('connect').textContent = `${owner.slice(0, 4)}…${owner.slice(-4)}`;
    return owner;
  } catch {
    toast('The wallet did not connect.');
    return null;
  }
}

// web3.js is only needed to hand the transaction to the wallet; load it on first launch.
let web3 = null;
function loadWeb3() {
  if (web3) return Promise.resolve(web3);
  return new Promise((ok, fail) => {
    const s = document.createElement('script');
    s.src = '/vendor/web3.js';
    s.onload = () => { web3 = window.solanaWeb3; ok(web3); };
    s.onerror = () => fail(new Error('Could not load the wallet library. Reload and try again.'));
    document.head.appendChild(s);
  });
}

// ---------- launch ----------

function setStatus(msg, kind = '') { const s = $('launch-status'); s.className = 'status ' + kind; s.textContent = msg; }

const b64ToBytes = (b) => Uint8Array.from(atob(b), (c) => c.charCodeAt(0));

let pending = null; // a paid draft that still needs to go live: retry without paying again

async function launch(e) {
  e.preventDefault();
  const form = $('launch-form');
  const btn = $('launch-btn');
  if (!owner && !(await connect())) return;
  btn.disabled = true;
  try {
    let draftId = pending?.draftId, sig = pending?.sig;
    if (!pending) {
      setStatus('Getting your coin ready…');
      const fd = new FormData(form);
      fd.set('owner', owner);
      const prep = await api('/api/launch/prepare', { method: 'POST', body: fd });
      const { VersionedTransaction } = await loadWeb3();
      const tx = VersionedTransaction.deserialize(b64ToBytes(prep.tx));
      setStatus(`Approve the ${prep.feeSol} SOL payment in your wallet…`);
      const sent = await wallet.signAndSendTransaction(tx);
      draftId = prep.draftId;
      sig = typeof sent === 'string' ? sent : sent.signature;
      pending = { draftId, sig };
    }
    setStatus('Payment sent. Creating your coin on pump.fun…');
    const done = await api('/api/launch/submit', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ draftId, sig }),
    });
    if (done.status === 'live') {
      pending = null;
      setStatus('Live. Opening it on pump.fun…', 'good');
      form.reset();
      loadBoard();
      window.open(done.url, '_blank', 'noopener');
    } else {
      setStatus(done.error || 'Still working on it. Press the button again in a few seconds.');
    }
  } catch (err) {
    const msg = /reject|denied|cancel/i.test(err?.message || '') ? 'You cancelled it in the wallet. Nothing was paid.' : err.message;
    if (/expired|not found|different/i.test(msg)) pending = null;
    setStatus(msg, 'bad');
  } finally {
    btn.disabled = false;
  }
}

// ---------- free scan ----------

const SEV = { high: 'high', med: 'medium', low: 'low' };
const LABEL = { safe: 'SAFE', caution: 'CAUTION', danger: 'DANGER' };

function renderReport(r) {
  const f = r.file || {};
  const v = r.verdict || { level: 'caution', summary: '' };
  const findings = r.findings || [];
  const hosts = (r.hosts || []).map((h) => `<span>${esc(h.host)}${h.note ? ' · ' + esc(h.note) : ''}</span>`).join('');
  const box = $('report');
  box.innerHTML = `
    <div class="head"><div><h3>${esc(f.name)}</h3><p>${esc(v.summary)}</p></div><div class="stamp ${esc(v.level)}">${LABEL[v.level] || esc(v.level)}</div></div>
    <div class="list-title">Findings (${findings.length})</div>
    ${findings.length ? findings.map((x) => `<div class="finding ${esc(x.severity)}"><span class="sev">${esc(SEV[x.severity] || x.severity)}</span>${esc(x.title)}${x.evidence ? `<span class="ev">${esc(x.evidence)}${x.file ? ' · ' + esc(x.file) : ''}</span>` : ''}</div>`).join('') : '<p>Nothing suspicious found. That is not a guarantee.</p>'}
    ${hosts ? `<div class="list-title">Servers it talks to</div><div class="chips">${hosts}</div>` : ''}
    <p><em>Read, never run. Pattern matching can miss well-hidden tricks.</em></p>`;
  box.hidden = false;
  box.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function scan(file) {
  if (!file) return;
  const drop = $('drop');
  drop.querySelector('strong').textContent = 'Reading…';
  try {
    const fd = new FormData();
    fd.append('file', file);
    renderReport(await api('/api/check', { method: 'POST', body: fd }));
  } catch (err) {
    toast(err.message);
  } finally {
    drop.querySelector('strong').textContent = 'Drop a file here';
  }
}

function wireDrop() {
  const drop = $('drop');
  $('scan-file').onchange = (e) => scan(e.target.files[0]);
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); scan(e.dataTransfer.files[0]); });
}

$('rea-check').addEventListener('submit', (e) => {
  e.preventDefault();
  const ca = $('rea-ca').value.trim();
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(ca)) return toast('That is not a Solana coin address.');
  location.href = `/c/${ca}`;
});
$('connect').onclick = connect;
$('launch-form').addEventListener('submit', launch);
wireDrop();
loadConfig();
loadBoard();
