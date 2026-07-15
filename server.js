const express = require('express');
const path = require('path');
const fs = require('fs');
const http = require('http');

const netplanDbus = require('./netplan-dbus');

const app = express();
const PORT = process.env.PORT || 7990;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'renderer')));

const SNAPD_SOCKET = '/run/snapd.socket';

function snapdRequest(method, apiPath, body = null) {
  return new Promise((resolve, reject) => {
    const options = {
      socketPath: SNAPD_SOCKET,
      path: apiPath,
      method,
      headers: { 'Host': 'localhost', 'Content-Type': 'application/json' }
    };
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error('Failed to parse snapd response: ' + data)); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

const dataDir = process.env.SNAP_MANAGER_DATA || __dirname;
const trackedFile = path.join(dataDir, 'tracked-snaps.json');

function readTracked() {
  try {
    if (fs.existsSync(trackedFile)) return JSON.parse(fs.readFileSync(trackedFile, 'utf8'));
  } catch (e) { console.error('read tracked:', e); }
  return [];
}
function writeTracked(list) {
  try { fs.writeFileSync(trackedFile, JSON.stringify(list, null, 2)); }
  catch (e) { console.error('write tracked:', e); }
}

// ===================== NETWORK SETUP (netplan via D-Bus) =====================
function buildNetplanYaml(config) {
  const netplan = { network: { version: 2, renderer: 'networkd', ethernets: {} } };
  for (const iface of config.interfaces) {
    const entry = {};
    if (iface.dhcp4) {
      entry.dhcp4 = true;
    } else {
      entry.dhcp4 = false;
      if (iface.addresses && iface.addresses.length) entry.addresses = iface.addresses;
      if (iface.gateway4) entry.routes = [{ to: 'default', via: iface.gateway4 }];
      if (iface.nameservers && iface.nameservers.length)
        entry.nameservers = { addresses: iface.nameservers };
    }
    netplan.network.ethernets[iface.name] = entry;
  }
  return toYaml(netplan);
}

function toYaml(obj, indent = 0) {
  let result = '';
  const pad = '  '.repeat(indent);
  if (Array.isArray(obj)) {
    for (const item of obj) {
      if (typeof item === 'object' && item !== null) {
        const entries = Object.entries(item);
        result += `${pad}- `;
        let first = true;
        for (const [k, v] of entries) {
          if (first) { result += `${k}: ${formatScalar(v)}\n`; first = false; }
          else { result += `${'  '.repeat(indent + 1)}${k}: ${formatScalar(v)}\n`; }
        }
      } else { result += `${pad}- ${formatScalar(item)}\n`; }
    }
  } else if (typeof obj === 'object' && obj !== null) {
    for (const [key, value] of Object.entries(obj)) {
      if (value === null || value === undefined) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        result += `${pad}${key}:\n${toYaml(value, indent + 1)}`;
      } else if (Array.isArray(value)) {
        const isScalarArray = value.every((v) => typeof v !== 'object');
        if (isScalarArray) result += `${pad}${key}: [${value.map(formatScalar).join(', ')}]\n`;
        else result += `${pad}${key}:\n${toYaml(value, indent + 1)}`;
      } else {
        result += `${pad}${key}: ${formatScalar(value)}\n`;
      }
    }
  }
  return result;
}
function formatScalar(v) {
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return String(v);
  return String(v);
}

app.get('/api/network/interfaces', (req, res) => {
  try {
    const os = require('os');
    res.json({ success: true, interfaces: Object.keys(os.networkInterfaces()) });
  } catch (err) { res.json({ success: false, error: err.message }); }
});

app.post('/api/network/preview', (req, res) => {
  try { res.json({ success: true, yaml: buildNetplanYaml(req.body) }); }
  catch (err) { res.json({ success: false, error: err.message }); }
});

app.post('/api/network/apply', async (req, res) => {
  try {
    const result = await netplanDbus.applyConfig(req.body);
    const yaml = buildNetplanYaml(req.body);
    res.json({ success: true, yaml, filePath: result.filePath, applyOutput: result.message });
  } catch (err) { res.json({ success: false, error: err.message }); }
});

app.post('/api/network/try', async (req, res) => {
  try {
    const timeout = req.body.timeout || 120;
    const result = await netplanDbus.tryConfig(req.body, timeout);
    res.json({ success: result.success, message: result.message });
  } catch (err) { res.json({ success: false, error: err.message }); }
});

app.get('/api/network/current', async (req, res) => {
  try { res.json(await netplanDbus.getConfig()); }
  catch (err) { res.json({ success: false, error: err.message }); }
});

// ============================ SNAP INSTALL =================================
app.get('/api/snap/search', async (req, res) => {
  try {
    const r = await snapdRequest('GET', `/v2/find?q=${encodeURIComponent(req.query.q || '')}`);
    if (r.type === 'error') return res.json({ success: false, error: r.result.message });
    res.json({ success: true, results: r.result });
  } catch (err) { res.json({ success: false, error: err.message }); }
});

app.post('/api/snap/install', async (req, res) => {
  try {
    const name = req.body.name;
    const r = await snapdRequest('POST', `/v2/snaps/${encodeURIComponent(name)}`, { action: 'install' });
    if (r.type === 'error') return res.json({ success: false, error: r.result.message });
    const tracked = readTracked();
    if (!tracked.find((s) => s.name === name)) {
      tracked.push({ name, installedAt: new Date().toISOString() });
      writeTracked(tracked);
    }
    res.json({ success: true, changeId: r.change, status: r.status });
  } catch (err) { res.json({ success: false, error: err.message }); }
});

app.post('/api/snap/remove', async (req, res) => {
  try {
    const name = req.body.name;
    const r = await snapdRequest('POST', `/v2/snaps/${encodeURIComponent(name)}`, { action: 'remove' });
    if (r.type === 'error') return res.json({ success: false, error: r.result.message });
    writeTracked(readTracked().filter((s) => s.name !== name));
    res.json({ success: true, changeId: r.change });
  } catch (err) { res.json({ success: false, error: err.message }); }
});

app.get('/api/snap/tracked', (req, res) => {
  res.json({ success: true, tracked: readTracked() });
});

app.get('/api/snap/change/:id', async (req, res) => {
  try {
    const r = await snapdRequest('GET', `/v2/changes/${req.params.id}`);
    res.json({ success: true, change: r.result });
  } catch (err) { res.json({ success: false, error: err.message }); }
});

// ======================= INTERFACE CONNECTIONS ============================
app.get('/api/connections', async (req, res) => {
  try {
    const r = await snapdRequest('GET', '/v2/connections?select=all');
    if (r.type === 'error') return res.json({ success: false, error: r.result.message });
    res.json({ success: true, data: r.result });
  } catch (err) { res.json({ success: false, error: err.message }); }
});

app.post('/api/connections/connect', async (req, res) => {
  try {
    const { plug, slot } = req.body;
    const body = { action: 'connect', plugs: [{ snap: plug.snap, plug: plug.plug }], slots: [{ snap: slot.snap, slot: slot.slot }] };
    const r = await snapdRequest('POST', '/v2/interfaces', body);
    if (r.type === 'error') return res.json({ success: false, error: r.result.message });
    res.json({ success: true, changeId: r.change });
  } catch (err) { res.json({ success: false, error: err.message }); }
});

app.post('/api/connections/disconnect', async (req, res) => {
  try {
    const { plug, slot } = req.body;
    const body = { action: 'disconnect', plugs: [{ snap: plug.snap, plug: plug.plug }], slots: [{ snap: slot.snap, slot: slot.slot }] };
    const r = await snapdRequest('POST', '/v2/interfaces', body);
    if (r.type === 'error') return res.json({ success: false, error: r.result.message });
    res.json({ success: true, changeId: r.change });
  } catch (err) { res.json({ success: false, error: err.message }); }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`ubuntu-core-manager listening on port ${PORT}`);
});
