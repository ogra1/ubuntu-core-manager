'use strict';

const dbus = require('dbus-native');

const NETPLAN_SERVICE = 'io.netplan.Netplan';
const NETPLAN_OBJECT = '/io/netplan/Netplan';
const NETPLAN_IFACE = 'io.netplan.Netplan';
const NETPLAN_CONFIG_IFACE = 'io.netplan.Netplan.Config';
const ORIGIN_HINT = '99-ubuntu-core-manager';

function getSystemBus() { return dbus.systemBus(); }

function invoke(bus, objectPath, iface, member, signature, args) {
  return new Promise((resolve, reject) => {
    bus.invoke(
      { destination: NETPLAN_SERVICE, path: objectPath, interface: iface,
        member: member, signature: signature || '', body: args || [] },
      (err, result) => {
        if (err) return reject(normalizeDbusError(err));
        resolve(result);
      }
    );
  });
}

function normalizeDbusError(err) {
  if (err instanceof Error) return err;
  if (Array.isArray(err)) return new Error(err.join(': '));
  if (typeof err === 'object' && err !== null) return new Error(err.message || JSON.stringify(err));
  return new Error(String(err));
}

function buildSetDeltas(config) {
  const deltas = [];
  for (const iface of config.interfaces) {
    const entry = {};
    if (iface.dhcp4) {
      entry.dhcp4 = true;
    } else {
      entry.dhcp4 = false;
      if (iface.addresses && iface.addresses.length) entry.addresses = iface.addresses;
      if (iface.gateway4) entry.routes = [{ to: 'default', via: iface.gateway4 }];
      if (iface.nameservers && iface.nameservers.length) entry.nameservers = { addresses: iface.nameservers };
    }
    const literal = JSON.stringify(entry);
    deltas.push(`network.ethernets.${iface.name}=${literal}`);
  }
  return deltas;
}

async function applyConfig(config) {
  const bus = getSystemBus();
  try {
    const configPathResult = await invoke(bus, NETPLAN_OBJECT, NETPLAN_IFACE, 'Config', '', []);
    const configPath = Array.isArray(configPathResult) ? configPathResult[0] : configPathResult;
    if (!configPath) throw new Error('netplan D-Bus: Config() returned no object path');

    const deltas = buildSetDeltas(config);
    if (deltas.length === 0) throw new Error('No interface configuration provided');

    for (const delta of deltas) {
      const setResult = await invoke(bus, configPath, NETPLAN_CONFIG_IFACE, 'Set', 'ss', [delta, ORIGIN_HINT]);
      const ok = Array.isArray(setResult) ? setResult[0] : setResult;
      if (!ok) { await tryCancel(bus, configPath); throw new Error(`netplan Set() failed for delta: ${delta}`); }
    }

    const applyResult = await invoke(bus, configPath, NETPLAN_CONFIG_IFACE, 'Apply', '', []);
    const applied = Array.isArray(applyResult) ? applyResult[0] : applyResult;
    if (!applied) throw new Error('netplan Apply() reported failure');

    return { success: true, filePath: `/etc/netplan/${ORIGIN_HINT}.yaml`, message: 'Configuration applied via netplan D-Bus API' };
  } finally {
    try { bus.connection.end(); } catch (_) {}
  }
}

async function tryConfig(config, timeoutSeconds = 120) {
  const bus = getSystemBus();
  try {
    const configPathResult = await invoke(bus, NETPLAN_OBJECT, NETPLAN_IFACE, 'Config', '', []);
    const configPath = Array.isArray(configPathResult) ? configPathResult[0] : configPathResult;
    const deltas = buildSetDeltas(config);
    for (const delta of deltas) {
      await invoke(bus, configPath, NETPLAN_CONFIG_IFACE, 'Set', 'ss', [delta, ORIGIN_HINT]);
    }
    const tryResult = await invoke(bus, configPath, NETPLAN_CONFIG_IFACE, 'Try', 'u', [timeoutSeconds]);
    const ok = Array.isArray(tryResult) ? tryResult[0] : tryResult;
    return { success: !!ok, configPath, message: `netplan Try() started (timeout ${timeoutSeconds}s)` };
  } finally {
    try { bus.connection.end(); } catch (_) {}
  }
}

async function tryCancel(bus, configPath) {
  try { await invoke(bus, configPath, NETPLAN_CONFIG_IFACE, 'Cancel', '', []); } catch (_) {}
}

async function getConfig() {
  const bus = getSystemBus();
  try {
    const result = await invoke(bus, NETPLAN_OBJECT, NETPLAN_IFACE, 'Get', '', []);
    const yaml = Array.isArray(result) ? result[0] : result;
    return { success: true, yaml: yaml || '' };
  } finally {
    try { bus.connection.end(); } catch (_) {}
  }
}

module.exports = { applyConfig, tryConfig, getConfig, buildSetDeltas, ORIGIN_HINT };
