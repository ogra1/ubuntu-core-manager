const api = {
  listInterfaces: () => fetch('/api/network/interfaces').then(r => r.json()),
  previewNetplan: (cfg) => post('/api/network/preview', cfg),
  applyNetplan: (cfg) => post('/api/network/apply', cfg),
  tryNetplan: (cfg) => post('/api/network/try', cfg),
  snapSearch: (q) => fetch('/api/snap/search?q=' + encodeURIComponent(q)).then(r => r.json()),
  snapInstall: (name) => post('/api/snap/install', { name }),
  snapRemove: (name) => post('/api/snap/remove', { name }),
  snapTracked: () => fetch('/api/snap/tracked').then(r => r.json()),
  snapChangeStatus: (id) => fetch('/api/snap/change/' + id).then(r => r.json()),
  connectionsList: () => fetch('/api/connections').then(r => r.json()),
  connectionsConnect: (d) => post('/api/connections/connect', d),
  connectionsDisconnect: (d) => post('/api/connections/disconnect', d)
};
function post(url, body) {
  return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(r => r.json());
}

const menuItems = document.querySelectorAll('.sidebar li');
const pages = document.querySelectorAll('.page');
menuItems.forEach((item) => {
  item.addEventListener('click', () => {
    menuItems.forEach((i) => i.classList.remove('active'));
    pages.forEach((p) => p.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('page-' + item.dataset.page).classList.add('active');
    if (item.dataset.page === 'snap') loadTracked();
    if (item.dataset.page === 'connections') loadConnections();
  });
});

function showStatus(elId, msg, ok = true) {
  const el = document.getElementById(elId);
  el.textContent = msg;
  el.className = 'status show ' + (ok ? 'ok' : 'err');
}

const ifaceList = document.getElementById('iface-list');
let ifaceCounter = 0;

function createIfaceCard(name = '') {
  const card = document.createElement('div');
  card.className = 'iface-card';
  card.dataset.id = 'iface-' + ifaceCounter++;
  card.innerHTML = `
    <div class="row">
      <label>Interface Name
        <input type="text" class="if-name" placeholder="eth0" value="${name}" />
      </label>
      <label class="checkbox-row" style="flex-direction:row;align-items:center;margin-top:18px;">
        <input type="checkbox" class="if-dhcp" checked /> DHCP (IPv4)
      </label>
      <button class="danger remove-iface">Remove</button>
    </div>
    <div class="row static-fields" style="display:none;">
      <label>Address/CIDR
        <input type="text" class="if-address" placeholder="192.168.1.50/24" />
      </label>
      <label>Gateway
        <input type="text" class="if-gateway" placeholder="192.168.1.1" />
      </label>
      <label>Nameservers (comma sep)
        <input type="text" class="if-dns" placeholder="8.8.8.8, 1.1.1.1" />
      </label>
    </div>
  `;
  const dhcp = card.querySelector('.if-dhcp');
  const staticFields = card.querySelector('.static-fields');
  dhcp.addEventListener('change', () => { staticFields.style.display = dhcp.checked ? 'none' : 'flex'; });
  card.querySelector('.remove-iface').addEventListener('click', () => card.remove());
  ifaceList.appendChild(card);
}

document.getElementById('btn-add-iface').addEventListener('click', () => createIfaceCard());
document.getElementById('btn-refresh-iface').addEventListener('click', async () => {
  const res = await api.listInterfaces();
  if (res.success) {
    ifaceList.innerHTML = '';
    res.interfaces.filter((n) => n !== 'lo').forEach((n) => createIfaceCard(n));
  }
});

function collectNetworkConfig() {
  const interfaces = [];
  document.querySelectorAll('.iface-card').forEach((card) => {
    const name = card.querySelector('.if-name').value.trim();
    if (!name) return;
    const dhcp4 = card.querySelector('.if-dhcp').checked;
    const iface = { name, dhcp4 };
    if (!dhcp4) {
      const addr = card.querySelector('.if-address').value.trim();
      const gw = card.querySelector('.if-gateway').value.trim();
      const dns = card.querySelector('.if-dns').value.trim();
      iface.addresses = addr ? [addr] : [];
      if (gw) iface.gateway4 = gw;
      iface.nameservers = dns ? dns.split(',').map((s) => s.trim()).filter(Boolean) : [];
    }
    interfaces.push(iface);
  });
  return { interfaces };
}

document.getElementById('btn-preview').addEventListener('click', async () => {
  const res = await api.previewNetplan(collectNetworkConfig());
  if (res.success) document.getElementById('netplan-output').textContent = res.yaml;
  else showStatus('net-status', res.error, false);
});

document.getElementById('btn-try').addEventListener('click', async () => {
  const cfg = collectNetworkConfig();
  if (cfg.interfaces.length === 0) { showStatus('net-status', 'Please add at least one interface.', false); return; }
  showStatus('net-status', 'Trying configuration (auto-rollback in 120s if not confirmed)...', true);
  const res = await api.tryNetplan(cfg);
  if (res.success) showStatus('net-status', res.message + ' — apply permanently to keep it.', true);
  else showStatus('net-status', 'Error: ' + res.error, false);
});

document.getElementById('btn-apply').addEventListener('click', async () => {
  const cfg = collectNetworkConfig();
  if (cfg.interfaces.length === 0) { showStatus('net-status', 'Please add at least one interface.', false); return; }
  showStatus('net-status', 'Applying netplan configuration...', true);
  const res = await api.applyNetplan(cfg);
  if (res.success) {
    document.getElementById('netplan-output').textContent = res.yaml;
    showStatus('net-status', `Saved to ${res.filePath} and applied.\n${res.applyOutput}`, true);
  } else {
    showStatus('net-status', 'Error: ' + res.error, false);
  }
});
createIfaceCard();

const snapResults = document.getElementById('snap-results');
const snapTracked = document.getElementById('snap-tracked');

async function doSnapSearch() {
  const query = document.getElementById('snap-search-input').value.trim();
  if (!query) return;
  snapResults.innerHTML = '<p class="spinner">Searching...</p>';
  const res = await api.snapSearch(query);
  if (!res.success) { snapResults.innerHTML = ''; showStatus('snap-status', 'Search error: ' + res.error, false); return; }
  renderSnapResults(res.results || []);
}

function renderSnapResults(results) {
  snapResults.innerHTML = '';
  if (results.length === 0) { snapResults.innerHTML = '<p>No results.</p>'; return; }
  results.slice(0, 30).forEach((snap) => {
    const publisher = (snap.publisher && (snap.publisher['display-name'] || snap.publisher.username)) || 'unknown';
    const div = document.createElement('div');
    div.className = 'snap-item';
    div.innerHTML = `
      <div class="snap-title">${escapeHtml(snap.title || snap.name)}</div>
      <div class="snap-publisher">${escapeHtml(snap.name)} • ${escapeHtml(publisher)}</div>
      <div class="snap-summary">${escapeHtml(snap.summary || '')}</div>
      <div class="snap-actions"><button class="primary install-btn">Install</button></div>
      <div class="progress-wrap" style="display:none;">
        <div class="progress-bar"><div class="progress-fill"></div></div>
        <div class="progress-label"></div>
      </div>
    `;
    div.querySelector('.install-btn').addEventListener('click', async (e) => {
      e.target.disabled = true; e.target.textContent = 'Installing...';
      const progressWrap = div.querySelector('.progress-wrap');
      progressWrap.style.display = 'block';
      const r = await api.snapInstall(snap.name);
      if (r.success) { showStatus('snap-status', `Install started for "${snap.name}".`, true); pollChange(r.changeId, snap.name, e.target, div); }
      else { showStatus('snap-status', 'Install error: ' + r.error, false); e.target.disabled = false; e.target.textContent = 'Install'; progressWrap.style.display = 'none'; }
    });
    snapResults.appendChild(div);
  });
}

function pollChange(changeId, name, btn, cardEl) {
  const fill = cardEl ? cardEl.querySelector('.progress-fill') : null;
  const label = cardEl ? cardEl.querySelector('.progress-label') : null;
  const interval = setInterval(async () => {
    const res = await api.snapChangeStatus(changeId);
    if (!res.success || !res.change) return;
    const change = res.change;
    let done = 0, total = 0, activeTask = '';
    (change.tasks || []).forEach((t) => {
      if (t.progress) { done += t.progress.done || 0; total += t.progress.total || 0; }
      if (t.status === 'Doing') activeTask = t.summary || '';
    });
    let pct = total > 0 ? Math.round((done / total) * 100) : 0;
    if (fill) fill.style.width = pct + '%';
    if (label) label.textContent = `${change.status} — ${activeTask || change.summary} (${pct}%)`;
    if (change.status === 'Done') {
      clearInterval(interval);
      if (fill) fill.style.width = '100%';
      if (label) label.textContent = 'Done (100%)';
      if (btn) btn.textContent = 'Installed';
      showStatus('snap-status', `"${name}" installed successfully.`, true);
      loadTracked();
    } else if (['Error', 'Abort', 'Hold'].includes(change.status)) {
      clearInterval(interval);
      if (label) label.textContent = 'Failed: ' + change.status;
      if (btn) { btn.disabled = false; btn.textContent = 'Install'; }
      showStatus('snap-status', `Install of "${name}" ended: ${change.status}`, false);
    }
  }, 1000);
}

document.getElementById('snap-search-btn').addEventListener('click', doSnapSearch);
document.getElementById('snap-search-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') doSnapSearch(); });

async function loadTracked() {
  const res = await api.snapTracked();
  snapTracked.innerHTML = '';
  if (!res.success || res.tracked.length === 0) { snapTracked.innerHTML = '<p>No snaps tracked yet.</p>'; return; }
  res.tracked.forEach((snap) => {
    const div = document.createElement('div');
    div.className = 'snap-item';
    div.innerHTML = `
      <div class="snap-title">${escapeHtml(snap.name)}</div>
      <div class="snap-publisher">Installed: ${new Date(snap.installedAt).toLocaleString()}</div>
      <div class="snap-actions"><button class="danger remove-btn">Remove</button></div>
      <div class="progress-wrap" style="display:none;">
        <div class="progress-bar"><div class="progress-fill"></div></div>
        <div class="progress-label"></div>
      </div>
    `;
    div.querySelector('.remove-btn').addEventListener('click', async (e) => {
      e.target.disabled = true; e.target.textContent = 'Removing...';
      div.querySelector('.progress-wrap').style.display = 'block';
      const r = await api.snapRemove(snap.name);
      if (r.success) { showStatus('snap-status', `Removal of "${snap.name}" started.`, true); pollChange(r.changeId, snap.name, null, div); }
      else { showStatus('snap-status', 'Remove error: ' + r.error, false); e.target.disabled = false; e.target.textContent = 'Remove'; div.querySelector('.progress-wrap').style.display = 'none'; }
    });
    snapTracked.appendChild(div);
  });
}

const establishedEl = document.getElementById('connections-established');
const availableEl = document.getElementById('connections-available');
document.getElementById('btn-refresh-connections').addEventListener('click', loadConnections);

async function loadConnections() {
  establishedEl.innerHTML = '<p class="spinner">Loading...</p>';
  availableEl.innerHTML = '';
  const res = await api.connectionsList();
  if (!res.success) { establishedEl.innerHTML = ''; showStatus('conn-status', 'Error: ' + res.error, false); return; }
  renderEstablished(res.data.established || []);
  renderAvailable(res.data.plugs || [], res.data.slots || []);
}

function renderEstablished(connections) {
  establishedEl.innerHTML = '';
  if (connections.length === 0) { establishedEl.innerHTML = '<p>No established connections.</p>'; return; }
  connections.forEach((c) => {
    const div = document.createElement('div');
    div.className = 'conn-card';
    div.innerHTML = `
      <div class="conn-info">
        <b>${escapeHtml(c.plug.snap)}:${escapeHtml(c.plug.plug)}</b> ↔
        <b>${escapeHtml(c.slot.snap)}:${escapeHtml(c.slot.slot)}</b>
        (${escapeHtml(c.interface)})
      </div>
      <button class="danger disc-btn">Disconnect</button>
    `;
    div.querySelector('.disc-btn').addEventListener('click', async (e) => {
      e.target.disabled = true; e.target.textContent = 'Disconnecting...';
      const r = await api.connectionsDisconnect({ plug: { snap: c.plug.snap, plug: c.plug.plug }, slot: { snap: c.slot.snap, slot: c.slot.slot } });
      if (r.success) { showStatus('conn-status', 'Disconnected.', true); setTimeout(loadConnections, 1500); }
      else { showStatus('conn-status', 'Error: ' + r.error, false); e.target.disabled = false; e.target.textContent = 'Disconnect'; }
    });
    establishedEl.appendChild(div);
  });
}

function renderAvailable(plugs, slots) {
  availableEl.innerHTML = '';
  const unconnected = plugs.filter((p) => !p.connections || p.connections.length === 0);
  if (unconnected.length === 0) { availableEl.innerHTML = '<p>No unconnected plugs.</p>'; return; }
  unconnected.forEach((plug) => {
    const compatible = slots.filter((s) => s.interface === plug.interface);
    if (compatible.length === 0) return;
    const options = compatible.map((s) => `<option value="${s.snap}|${s.slot}">${escapeHtml(s.snap)}:${escapeHtml(s.slot)}</option>`).join('');
    const div = document.createElement('div');
    div.className = 'conn-card';
    div.innerHTML = `
      <div class="conn-info"><b>${escapeHtml(plug.snap)}:${escapeHtml(plug.plug)}</b> (${escapeHtml(plug.interface)})</div>
      <select class="slot-select">${options}</select>
      <button class="primary conn-btn">Connect</button>
    `;
    div.querySelector('.conn-btn').addEventListener('click', async (e) => {
      const [slotSnap, slotName] = div.querySelector('.slot-select').value.split('|');
      e.target.disabled = true; e.target.textContent = 'Connecting...';
      const r = await api.connectionsConnect({ plug: { snap: plug.snap, plug: plug.plug }, slot: { snap: slotSnap, slot: slotName } });
      if (r.success) { showStatus('conn-status', 'Connected.', true); setTimeout(loadConnections, 1500); }
      else { showStatus('conn-status', 'Error: ' + r.error, false); e.target.disabled = false; e.target.textContent = 'Connect'; }
    });
    availableEl.appendChild(div);
  });
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
