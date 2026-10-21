'use strict';
/*
 * Erkennung, Start/Stopp und der Dienst "vpn" – das System ist komplett nachgebildet: kein Programm läuft, keine
 * Administrator-Abfrage, keine Netzwerk-Einstellung wird berührt. Daten in einem Temp-Ordner.   node --test tests/
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WgSystem, installGuide } = require('../server/system');
const { VpnService } = require('../server/service');
const K = require('../server/keys');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'hw-vpn-'));
const secrets = {
  seal: (t) => (t ? `enc:${Buffer.from(String(t)).toString('base64').split('').reverse().join('')}` : ''),
  open: (v) => (v && String(v).startsWith('enc:') ? Buffer.from(String(v).slice(4).split('').reverse().join(''), 'base64').toString() : v || ''),
};
const WG_EXE = 'C:\\Program Files\\WireGuard\\wireguard.exe';
const WG_CLI = 'C:\\Program Files\\WireGuard\\wg.exe';

/** Nachgebildetes Windows/Linux: merkt sich jeden Aufruf, ändert nichts. */
function fakeSystem({ platform = 'win32', installed = true, running = false, service = false, elevatedCode = 0, tailscale = null, dump = '', prefs = null, zerotier = null, netbird = null, headscale = false, noBatch = false } = {}) {
  const calls = { run: [], elevated: [], batch: [] };
  const st = { running, service };
  const f = { calls, st, liveOk: false, version: null, dumpText: (d) => { dump = d; } };
  const files = new Set(installed ? (platform === 'win32' ? [WG_EXE, WG_CLI] : []) : []);
  if (tailscale && platform === 'win32') files.add('C:\\Program Files\\Tailscale\\tailscale.exe');
  if (zerotier && platform === 'win32') files.add('C:\\ProgramData\\ZeroTier\\One\\zerotier-one_x64.exe');
  if (netbird && platform === 'win32') files.add('C:\\Program Files\\Netbird\\netbird.exe');
  const elevate = (cmd, args) => { if (elevatedCode === 0) { if (args[0] === '/installtunnelservice' || args[0] === 'up') { st.running = true; st.service = true; } else if (args[0] === '/uninstalltunnelservice' || args[0] === 'down') { st.running = false; st.service = false; } } return elevatedCode; };
  f.sys = new WgSystem({
    platform,
    env: { ProgramFiles: 'C:\\Program Files', ProgramData: 'C:\\ProgramData' },
    exists: (p) => files.has(p) || (p === '/sys/class/net/hostwerk' && st.running),
    which: async (n) => (platform === 'linux' && installed && ['wg', 'wg-quick'].includes(n) ? `/usr/bin/${n}` : n === 'tailscale' && tailscale ? '/usr/bin/tailscale' : n === 'headscale' && headscale ? '/usr/bin/headscale' : null),
    run: async (cmd, args) => {
      calls.run.push([cmd, ...args]);
      if (cmd === 'sc') return st.service || st.running ? { code: 0, stdout: `SERVICE_NAME: WireGuardTunnel$hostwerk\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : ${st.running ? '4  RUNNING' : '1  STOPPED'}\n` } : { code: 1060, stdout: '[SC] EnumQueryServicesStatus:OpenService FAILED 1060' };
      if (cmd === 'powershell.exe') return f.version ? { code: 0, stdout: `${f.version}\r\n` } : { code: 1, stdout: '' };
      if (/wg(\.exe)?$/.test(cmd) && args[0] === 'set') return { code: f.liveOk ? 0 : 1, stdout: '' };
      if (/wg(\.exe)?$/.test(cmd) && args[0] === '--version') return { code: 0, stdout: 'wireguard-tools v1.0.20210914 - https://git.zx2c4.com/wireguard-tools/' };
      if (/wg(\.exe)?$/.test(cmd)) return dump ? { code: 0, stdout: dump } : { code: 1, stdout: '' };
      if (/tailscale/.test(cmd)) return args[0] === 'debug' ? (prefs ? { code: 0, stdout: JSON.stringify(prefs) } : { code: 1, stdout: '' }) : { code: 0, stdout: JSON.stringify(tailscale) };
      if (/zerotier/.test(cmd)) {
        if (zerotier === 'denied') return { code: 2, stdout: 'Error connecting to the ZeroTier service: Unable to read authentication token' };
        return args.includes('info') ? { code: 0, stdout: JSON.stringify({ address: 'abcdef0123', online: true, version: '1.14.2' }) } : { code: 0, stdout: JSON.stringify([{ nwid: '8056c2e21c000001', name: 'home', status: 'OK', assignedAddresses: ['10.147.17.5/24'] }]) };
      }
      if (/netbird/.test(cmd)) return { code: 0, stdout: JSON.stringify({ management: { connected: true, url: 'https://api.netbird.io:443' }, netbirdIp: '100.92.0.4/16', fqdn: 'pc.netbird.cloud', peers: { total: 3, connected: 2 }, daemonVersion: '0.30.1' }) };
      if (/headscale/.test(cmd)) return { code: 0, stdout: 'v0.23.0\n' };
      return { code: 1, stdout: '' };
    },
    elevated: async (cmd, args) => { calls.elevated.push([cmd, ...args]); return elevate(cmd, args); },
    batch: noBatch ? null : async (steps) => { calls.batch.push(steps); const code = elevate(steps[0].cmd, steps[0].args); return { code, steps: steps.map(() => ({ code, out: '' })) }; },
  });
  return f;
}

test('detect: Windows and Linux, installed or not, plus a guide', async () => {
  assert.deepStrictEqual(await fakeSystem().sys.detect(), { supported: true, installed: true, wireguard: WG_EXE, wg: WG_CLI });
  assert.strictEqual((await fakeSystem({ installed: false }).sys.detect()).installed, false);
  assert.deepStrictEqual(await fakeSystem({ platform: 'linux' }).sys.detect(), { supported: true, installed: true, wgQuick: '/usr/bin/wg-quick', wg: '/usr/bin/wg' });
  assert.deepStrictEqual(await fakeSystem({ platform: 'darwin' }).sys.detect(), { supported: false, installed: false });
  assert.strictEqual(installGuide('win32').command, 'winget install WireGuard.WireGuard');
  assert.strictEqual(installGuide('linux', () => 'sudo dnf install wireguard-tools').command, 'sudo dnf install wireguard-tools');
  assert.strictEqual(installGuide('darwin').command, '');
});

test('tunnel state from sc query / /sys, handshakes from wg show dump', async () => {
  const f = fakeSystem({ running: true, dump: 'priv\tpub\t51820\toff\nPEER1\tpsk\t198.51.100.7:4242\t10.66.66.2/32\t1760000000\t1200\t3400\t25\nPEER2\tpsk\t(none)\t10.66.66.3/32\t0\t0\t0\t25\n' });
  const det = await f.sys.detect();
  assert.deepStrictEqual(await f.sys.tunnel(det), { running: true, service: true });
  assert.deepStrictEqual(f.calls.run[0], ['sc', 'query', 'WireGuardTunnel$hostwerk']);
  assert.deepStrictEqual(await f.sys.handshakes(det), { PEER1: { endpoint: '198.51.100.7:4242', allowed: '10.66.66.2/32', lastHandshake: 1760000000000, rx: 1200, tx: 3400 }, PEER2: { endpoint: null, allowed: '10.66.66.3/32', lastHandshake: null, rx: 0, tx: 0 } });
  assert.deepStrictEqual(await fakeSystem().sys.tunnel(det), { running: false, service: false });
  assert.deepStrictEqual(await fakeSystem({ service: true }).sys.tunnel(det), { running: false, service: true });
  assert.deepStrictEqual(await fakeSystem({ running: true }).sys.handshakes(det), {}, 'no rights → no handshakes, no error');
  const l = fakeSystem({ platform: 'linux', running: true });
  assert.strictEqual((await l.sys.tunnel(await l.sys.detect())).running, true);
});

test('tailscale: read-only status', async () => {
  const ts = { BackendState: 'Running', Self: { HostName: 'pc', DNSName: 'pc.tail1234.ts.net.', TailscaleIPs: ['100.101.102.103'] }, CurrentTailnet: { Name: 'me@example.com' }, Peer: { a: { Online: true }, b: { Online: false } } };
  const f = fakeSystem({ tailscale: ts });
  const got = await f.sys.tailscale();
  assert.deepStrictEqual([got.installed, got.running, got.state, got.name, got.dnsName, got.ips, got.tailnet, got.peers, got.online], [true, true, 'Running', 'pc', 'pc.tail1234.ts.net', ['100.101.102.103'], 'me@example.com', 2, 1]);
  assert.deepStrictEqual([got.controlUrl, got.headscale, got.advertises], [null, false, { exitNode: false, routes: [] }], 'old Tailscale without debug prefs');
  assert.deepStrictEqual(f.calls.run.find((c) => c.includes('status')).slice(1), ['status', '--json']);
  assert.deepStrictEqual(await fakeSystem().sys.tailscale(), { installed: false });
  assert.strictEqual((await fakeSystem({ platform: 'linux', tailscale: { BackendState: 'NeedsLogin' } }).sys.tailscale()).running, false);
});

function service(opts = {}, ctx = {}) {
  const f = fakeSystem(opts);
  const dir = tmp();
  const svc = new VpnService({ dir, secrets, system: f.sys, qr: async (t) => `<svg data-len="${t.length}"/>`, ctx, platform: opts.platform || 'win32', fetch: null });
  return Object.assign(f, { svc, dir });
}

test('state: server key made once and only sealed on disk; accesses get keys and addresses', async () => {
  const { svc, dir } = service();
  const st = await svc.status();
  assert.ok(K.isKey(st.serverPublicKey));
  assert.strictEqual(st.serverAddress, '10.66.66.1');
  assert.strictEqual((await svc.status()).serverPublicKey, st.serverPublicKey, 'same key next time');
  const lena = svc.addPeer({ person: 'Lena', device: 'Handy' });
  const tom = svc.addPeer({ person: 'Tom' });
  assert.deepStrictEqual([lena.address, tom.address], ['10.66.66.2', '10.66.66.3']);
  assert.ok(!('privateKey' in lena));
  assert.throws(() => svc.addPeer({ person: 'lena', device: 'handy' }), (e) => e.status === 409);
  assert.throws(() => svc.addPeer({ person: ' ' }), (e) => e.status === 400);
  const disk = JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8'));
  assert.ok(disk.server.privateKey.startsWith('enc:'));
  assert.ok(disk.peers.every((p) => p.privateKey.startsWith('enc:') && p.presharedKey.startsWith('enc:')));
  assert.ok(!JSON.stringify(await svc.status()).includes(secrets.open(disk.peers[0].privateKey)), 'status never contains a private key');
  // ändern, neue Schlüssel, entfernen – Adresse wird wieder frei
  assert.strictEqual(svc.updatePeer(tom.id, { enabled: false }).enabled, false);
  const re = svc.rekeyPeer(lena.id);
  assert.notStrictEqual(re.publicKey, lena.publicKey);
  svc.removePeer(lena.id);
  assert.strictEqual(svc.addPeer({ person: 'Mia' }).address, '10.66.66.2');
  assert.throws(() => svc.removePeer('nope'), (e) => e.status === 404);
});

test('team: accesses can belong to a member of “Team & roles”', async () => {
  const users = { list: [{ id: 'u1', name: 'Lena', enabled: true }, { id: 'u2', name: 'Old', enabled: false }] };
  const { svc } = service({}, { users });
  assert.deepStrictEqual(svc.members(), [{ id: 'u1', name: 'Lena' }]);
  assert.strictEqual((await svc.status()).team, true);
  assert.strictEqual(svc.addPeer({ person: 'Lena', member: 'u1' }).member, 'u1');
  assert.throws(() => svc.addPeer({ person: 'X', member: 'u9' }), (e) => e.status === 404);
  assert.deepStrictEqual(service().svc.members(), []);
});

test('device configuration with QR code; endpoint suggestion from the router extension', async () => {
  const router = { dyn: { domain: '' }, net: async () => ({ v4public: '203.0.113.5' }) };
  const { svc } = service({}, { router });
  const p = svc.addPeer({ person: 'Lena', device: 'Handy' });
  await assert.rejects(svc.config(p.id), (e) => e.status === 409, 'no endpoint yet');
  assert.deepStrictEqual(await svc.suggestEndpoint(), { endpoint: '203.0.113.5', source: 'ip' });
  router.dyn.domain = 'me.dyndns.example';
  assert.deepStrictEqual(await svc.suggestEndpoint(), { endpoint: 'me.dyndns.example', source: 'dyndns' });
  await svc.saveSettings({ endpoint: 'me.dyndns.example' });
  const c = await svc.config(p.id);
  assert.strictEqual(c.file, 'hw-lena-handy.conf');
  assert.match(c.text, /Endpoint = me\.dyndns\.example:51820/);
  const priv = c.text.match(/PrivateKey = (\S+)/)[1];
  assert.strictEqual(K.publicKey(priv), p.publicKey, 'the device key belongs to the access');
  assert.match(c.qr, /^<svg data-len="\d+"\/>$/);
  await assert.rejects(service().svc.saveSettings({ scope: 'lan', lanSubnet: '192.168.1.0/24' }), /needs Linux/);
});

test('start/stop (Windows): only with confirmation, conf file only while running, admin prompt via elevated', async () => {
  const { svc, dir, calls } = service();
  await svc.saveSettings({ endpoint: 'home.example.com' });
  await assert.rejects(svc.start({}), (e) => e.status === 428);
  await assert.rejects(svc.start({ confirm: true }), /Add an access first/);
  svc.addPeer({ person: 'Lena' });
  assert.strictEqual(calls.elevated.length, 0, 'nothing ran without confirmation');
  const st = await svc.start({ confirm: true });
  const conf = path.join(dir, 'hostwerk.conf');
  assert.deepStrictEqual(calls.elevated[0], [WG_EXE, '/installtunnelservice', conf]);
  assert.strictEqual(st.wireguard.running, true);
  assert.strictEqual(st.needsRestart, false);
  assert.match(fs.readFileSync(conf, 'utf8'), /\[Peer\]/);
  if (process.platform !== 'win32') assert.strictEqual(fs.statSync(conf).mode & 0o077, 0, 'only the owner may read the key file');
  await assert.rejects(svc.start({ confirm: true }), /running already/);
  svc.addPeer({ person: 'Tom' });
  assert.strictEqual((await svc.status()).needsRestart, true, 'changes while running need a restart');
  await assert.rejects(svc.stop({}), (e) => e.status === 428);
  const off = await svc.stop({ confirm: true });
  assert.deepStrictEqual(calls.elevated[1], [WG_EXE, '/uninstalltunnelservice', 'hostwerk']);
  assert.strictEqual(off.wireguard.running, false);
  assert.ok(!fs.existsSync(conf), 'key file is gone after stopping');
});

test('start: declined admin prompt leaves nothing behind and offers the manual command', async () => {
  const { svc, dir } = service({ elevatedCode: 1223 });
  await svc.saveSettings({ endpoint: 'home.example.com' });
  svc.addPeer({ person: 'Lena' });
  await assert.rejects(svc.start({ confirm: true }), (e) => e.status === 409 && e.vars.code === 1223 && /installtunnelservice/.test(e.manual));
  assert.ok(!fs.existsSync(path.join(dir, 'hostwerk.conf')));
  const none = service({ installed: false });
  none.svc.addPeer({ person: 'Lena' });
  await assert.rejects(none.svc.start({ confirm: true }), /not installed/);
  const st = await none.svc.status();
  assert.strictEqual(st.wireguard.installed, false);
  assert.ok(st.wireguard.guide.steps.length);
});

test('start/stop (Linux): wg-quick up/down through pkexec', async () => {
  const { svc, dir, calls } = service({ platform: 'linux' });
  await svc.saveSettings({ endpoint: 'home.example.com', scope: 'lan', lanSubnet: '192.168.178.0/24' });
  svc.addPeer({ person: 'Lena' });
  await svc.start({ confirm: true });
  const conf = path.join(dir, 'hostwerk.conf');
  assert.deepStrictEqual(calls.elevated[0], ['/usr/bin/wg-quick', 'up', conf]);
  assert.match(fs.readFileSync(conf, 'utf8'), /PostUp = /);
  await svc.stop({ confirm: true });
  assert.deepStrictEqual(calls.elevated[1], ['/usr/bin/wg-quick', 'down', conf]);
});

test('router: forwards the UDP port and remembers it there', async () => {
  const forwarded = [];
  let saved = 0;
  const router = { cfg: { extra: [{ port: 25565, protocol: 'TCP', label: 'MC' }] }, forward: async (x) => { forwarded.push(x); return { port: x.port, protocol: x.protocol, client: '192.168.178.20' }; } };
  const { svc } = service({}, { router, settings: { save: () => { saved++; } } });
  const r = await svc.forward();
  assert.deepStrictEqual(forwarded, [{ port: 51820, protocol: 'UDP', label: 'WireGuard (VPN)' }]);
  assert.strictEqual(r.port, 51820);
  assert.deepStrictEqual(router.cfg.extra.map((e) => `${e.port}/${e.protocol}`), ['25565/TCP', '51820/UDP']);
  assert.strictEqual(saved, 1);
  await assert.rejects(service().svc.forward(), (e) => e.status === 409);
});

test('activate: provides "vpn" and registers the routes without touching the system', async () => {
  const dir = tmp();
  const routes = {}; const provided = {};
  const reg = (m) => (p, h) => { routes[`${m} ${p}`] = h; };
  let elevatedCalls = 0;
  const host = {
    ctx: { paths: { data: dir } },
    router: { get: reg('GET'), post: reg('POST'), put: reg('PUT'), delete: reg('DELETE') },
    core: (n) => (n === 'secrets' ? secrets : { elevated: async () => { elevatedCalls++; return 0; }, which: async () => null, pkgHint: () => '' }),
    lib: (n) => { assert.strictEqual(n, 'qrcode'); return { toString: async () => '<svg/>' }; },
    provide: (n, o) => { provided[n] = o; },
    error: (status, text, vars, extra) => Object.assign(new Error(text), { status }, extra || {}),
    t: (s) => s, broadcast: () => {}, log: () => {}, on: () => () => {},
  };
  const mod = require('../server/index');
  mod.activate(host);
  assert.ok(provided.vpn instanceof VpnService);
  for (const k of ['GET /vpn', 'PUT /vpn/settings', 'GET /vpn/endpoint-suggestion', 'GET /vpn/members', 'POST /vpn/peers', 'PUT /vpn/peers/:id', 'POST /vpn/peers/:id/rekey', 'DELETE /vpn/peers/:id', 'GET /vpn/peers/:id/config', 'POST /vpn/start', 'POST /vpn/stop', 'POST /vpn/forward', 'GET /vpn/others', 'POST /vpn/check']) assert.ok(routes[k], k);
  await assert.rejects(routes['POST /vpn/start']({ body: {} }, {}), (e) => e.status === 428);
  await assert.rejects(routes['DELETE /vpn/peers/:id']({ params: { id: 'x' } }, {}), (e) => e.status === 404);
  assert.strictEqual(elevatedCalls, 0);
  mod.deactivate();
});

/* ---------------- 1.1: Wartung, mehr VPNs, Zugänge mit Reichweite ---------------- */
const M = require('../server/maint');

test('maintenance helpers: latest Windows version, version compare, expiry, key age', () => {
  const sig = 'untrusted comment: signify\nRWR…\n1f2e  wireguard-amd64-0.5.3.msi\n3a4b  wireguard-arm64-0.5.3.msi\n9c8d  wireguard-x86-0.5.3.msi\n';
  assert.strictEqual(M.parseLatestWindows(sig), '0.5.3');
  assert.strictEqual(M.parseLatestWindows('wireguard-amd64-0.5.10.msi\nwireguard-amd64-0.5.9.msi'), '0.5.10');
  assert.strictEqual(M.parseLatestWindows('nothing here'), null);
  assert.ok(M.newer('0.5.10', '0.5.3')); assert.ok(!M.newer('0.5.3', '0.5.3')); assert.ok(!M.newer('0.4', '0.5.3')); assert.ok(M.newer('1.0', '0.9.9'));
  const now = 1_800_000_000_000;
  const peers = [{ id: 'a', expires: now - 1 }, { id: 'b', expires: now + 1 }, { id: 'c', expires: now - 1, lock: { reason: 'expired' } }, { id: 'd' }];
  assert.deepStrictEqual(M.expiredPeers(peers, now).map((p) => p.id), ['a']);
  const keys = [{ id: 'old', keyAt: now - 13 * M.MONTH }, { id: 'new', keyAt: now - M.MONTH }, { id: 'off', keyAt: 0, enabled: false }];
  assert.deepStrictEqual(M.rotationDue(keys, 12, now).map((p) => p.id), ['old']);
  assert.deepStrictEqual(M.rotationDue(keys, 0, now), []);
});

test('health: findings from the state, only new problems are reported', () => {
  const now = 1_800_000_000_000;
  const base = { installed: true, running: true, wantRunning: true, startedAt: now - 2 * M.DAY, settings: { endpoint: 'home.example.com', rotateMonths: 0 }, peers: [{ id: 'p', person: 'Lena', created: now - 3 * M.DAY }], now };
  assert.deepStrictEqual(M.assess({ ...base, peers: [{ ...base.peers[0], lastSeen: now - 1000 }] }), []);
  const ids = (x) => M.assess({ ...base, ...x }).map((i) => i.id);
  assert.deepStrictEqual(ids({}), ['silent']);
  assert.deepStrictEqual(ids({ running: false }), ['down']);
  assert.deepStrictEqual(ids({ running: false, wantRunning: false }), [], 'stopped on purpose is fine');
  assert.ok(ids({ settings: { endpoint: '' } }).includes('endpoint'));
  assert.ok(ids({ endpointCheck: { ipChanged: true } }).includes('ip-changed'));
  assert.ok(ids({ net: { cgnat: true, v6: false } }).includes('cgnat'));
  assert.ok(ids({ net: { dslite: true, v6: true } }).includes('dslite'));
  assert.ok(ids({ forward: { state: 'failed', error: 'x' } }).includes('forward'));
  assert.ok(ids({ update: { installed: '0.5.2', latest: '0.5.3' } }).includes('update'));
  assert.ok(!ids({ update: { installed: '0.5.3', latest: '0.5.3' } }).includes('update'));
  const issues = M.assess({ ...base, running: false, net: { cgnat: true } });
  assert.deepStrictEqual(M.fresh(issues, []).map((i) => i.id), ['down', 'cgnat']);
  assert.deepStrictEqual(M.fresh(issues, ['down', 'cgnat']), [], 'already reported');
  assert.deepStrictEqual(M.fresh(M.assess({ ...base }), []), [], 'hints alone never notify');
});

test('accesses 1.1: device type, reach, end date, lock – live in the running tunnel when the rights suffice', async () => {
  const f = service({ running: true, dump: 'priv\tpub\t51820\toff\n' });
  const { svc } = f;
  await svc.saveSettings({ endpoint: 'home.example.com' });
  const p = svc.addPeer({ person: 'Lena', device: 'Handy', platform: 'android', reach: 'services', services: [{ port: 25565, name: 'Minecraft' }], expires: Date.now() + 3600000 });
  assert.deepStrictEqual([p.platform, p.reach, p.services[0].port, !!p.expires, p.lock], ['android', 'services', 25565, true, null]);
  assert.throws(() => svc.addPeer({ person: 'Tom', reach: 'full' }), /needs Linux/);
  // gesperrt = nicht im Tunnel, entsperren bringt ihn zurück
  assert.strictEqual(svc.updatePeer(p.id, { locked: true }).lock.reason, 'manual');
  assert.ok(!svc.serverConfigText(svc.load()).includes(p.publicKey));
  assert.strictEqual(svc.updatePeer(p.id, { locked: false }).lock, null);
  // Live übernehmen: „wg set“ klappt (Rechte reichen) → kein Neustart nötig
  f.liveOk = true;
  const s = svc.load(); s.appliedRules = svc.rulesKey(s); svc.save(s);
  assert.strictEqual(await svc.syncLive(), true);
  assert.strictEqual(svc.load().needsRestart, false);
  const set = f.calls.run.filter((c) => c[1] === 'set');
  assert.deepStrictEqual(set[0].slice(1, 4), ['set', 'hostwerk', 'peer']);
  assert.ok(set[0].includes('allowed-ips') && set[0].includes(`${p.address}/32`) && set[0].includes('preshared-key'));
  assert.ok(!set[0].some((a) => a === secrets.open(svc.load().peers[0].presharedKey)), 'the preshared key never shows up in the command line');
  // Firewall-Regeln ändern sich (andere Dienste) → „wg set“ reicht nicht
  svc.updatePeer(p.id, { services: [{ port: 8080 }] });
  assert.strictEqual(await svc.syncLive(), false);
  assert.strictEqual(svc.load().needsRestart, true);
});

test('tick: expired accesses get locked, handshakes are remembered, findings bundled into ONE notification', async () => {
  const sent = []; const watch = [];
  const f = fakeSystem({ running: true });
  const dir = tmp();
  const svc = new VpnService({ dir, secrets, system: f.sys, qr: async () => '<svg/>', platform: 'win32', notify: (m) => sent.push(m), watcher: (w) => watch.push(w), fetch: async () => ({ ok: true, text: async () => 'x  wireguard-amd64-0.9.0.msi' }) });
  await svc.saveSettings({ endpoint: 'home.example.com' });
  const a = svc.addPeer({ person: 'Lena', expires: Date.now() + 60000 });
  const b = svc.addPeer({ person: 'Tom' });
  const s = svc.load(); s.peers[0].expires = Date.now() - 1000; s.wantRunning = true; s.startedAt = Date.now() - 3 * M.DAY; svc.save(s);
  f.dumpText(`priv\tpub\t51820\toff\n${b.publicKey}\tpsk\t198.51.100.7:4242\t${b.address}/32\t${Math.floor(Date.now() / 1000) - 30}\t1200\t3400\t25\n`);
  f.version = '0.5.3';
  const r = await svc.tick({ force: true });
  const st = await svc.status();
  assert.strictEqual(st.peers.find((p) => p.id === a.id).lock.reason, 'expired');
  const tom = st.peers.find((p) => p.id === b.id);
  assert.ok(tom.lastHandshake > Date.now() - 60000);
  assert.deepStrictEqual([tom.rx, tom.tx], [1200, 3400]);
  assert.ok(r.issues.some((i) => i.id === 'update'), 'update 0.5.3 → 0.9.0 is a hint');
  assert.strictEqual(sent.length, 0, 'hints alone send nothing');
  assert.strictEqual(watch.at(-1).state, 'ok');
  // Tunnel fällt aus → EINE Meldung; beim nächsten Durchgang nicht noch einmal
  f.st.running = false; f.st.service = false;
  await svc.tick();
  await svc.tick();
  assert.strictEqual(sent.length, 1);
  assert.match(sent[0].title, /not running/);
  assert.strictEqual(sent[0].kind, 'error');
  assert.strictEqual(watch.at(-1).state, 'alert');
  // remembered while the tunnel is off
  assert.ok((await svc.status()).peers.find((p) => p.id === b.id).lastHandshake);
  svc.dispose();
});

test('tick: own name kept up to date through the DNS extension, DynDNS name taken from the router, IP change noticed', async () => {
  const records = [];
  let ip = { v4public: '203.0.113.5', v6: { stable: '2001:db8::5' } };
  const router = { dyn: { domain: '' }, net: async () => ip, status: async () => ({ cgnat: false, dslite: false, net: { v6: { stable: ip.v6.stable }, v4public: ip.v4public }, externalIp: ip.v4public, wanted: [] }) };
  const dns = { set: async (r) => { records.push(`${r.type} ${r.name} ${r.content}`); return { action: 'created' }; } };
  const { svc } = service({}, { router, dns });
  await assert.rejects(svc.saveSettings({ endpointMode: 'dyndns' }), /no DynDNS name/);
  await svc.saveSettings({ endpointMode: 'dns', endpoint: 'vpn.example.com' });
  assert.deepStrictEqual(records, ['A vpn.example.com 203.0.113.5', 'AAAA vpn.example.com 2001:db8::5']);
  await svc.tick();
  assert.strictEqual(records.length, 2, 'nothing changed → no request');
  ip = { v4public: '203.0.113.99', v6: { stable: '2001:db8::5' } };
  await svc.tick();
  assert.deepStrictEqual(records.slice(2), ['A vpn.example.com 203.0.113.99', 'AAAA vpn.example.com 2001:db8::5']);
  assert.strictEqual((await svc.status()).dnsState.ok, true);
  dns.set = async () => { throw new Error('Zone not found'); };
  ip = { v4public: '203.0.113.100', v6: { stable: null } };
  const r = await svc.tick();
  assert.ok(r.issues.some((i) => i.id === 'dns' && /Zone not found/.test(i.text)));
  // DynDNS-Name der Router-Erweiterung
  router.dyn.domain = 'me.duckdns.org';
  await svc.saveSettings({ endpointMode: 'dyndns' });
  assert.strictEqual((await svc.status()).settings.endpoint, 'me.duckdns.org');
  // feste IP als Adresse → IP-Wechsel wird gemeldet
  await svc.saveSettings({ endpointMode: 'manual', endpoint: '203.0.113.5' });
  svc.addPeer({ person: 'Lena' });
  const r2 = await svc.tick({ force: true });
  assert.ok(r2.issues.some((i) => i.id === 'ip-changed'));
});

test('router: forwarding with owner "vpn" follows the tunnel (start → add, port change → move, stop → remove)', async () => {
  const fw = [];
  const router = { forward: async () => { throw new Error('old way must not be used'); }, forwards: {
    owned: (o) => fw.filter((x) => x.owner === o),
    add: async (x, o) => { if (x.port === 1) throw new Error('No router with UPnP or NAT-PMP found'); fw.splice(0, fw.length, ...fw.filter((y) => !(y.port === x.port && y.protocol === x.protocol)), { ...x, owner: o }); return x; },
    remove: async (x, o) => { const i = fw.findIndex((y) => y.port === x.port && y.protocol === x.protocol && y.owner === o); if (i < 0) return false; fw.splice(i, 1); return true; },
  } };
  const { svc } = service({}, { router });
  await svc.saveSettings({ endpoint: 'home.example.com' });
  svc.addPeer({ person: 'Lena' });
  await svc.start({ confirm: true });
  assert.deepStrictEqual(fw, [{ port: 51820, protocol: 'UDP', label: 'WireGuard (VPN)', owner: 'vpn' }]);
  assert.strictEqual((await svc.status()).forward.state, 'ok');
  await svc.saveSettings({ port: 51821 });
  assert.deepStrictEqual(fw.map((x) => x.port), [51821], 'old port removed, new one forwarded');
  await svc.stop({ confirm: true });
  assert.deepStrictEqual(fw, [], 'stopping removes the own forwarding');
  // Fehler beim Freigeben → Befund mit verständlichem Text
  const r = await svc.forward().catch((e) => e);
  assert.strictEqual(r.port, 51821);
  const s = svc.load(); s.settings.port = 1; svc.save(s);
  await assert.rejects(svc.forward(), /UPnP/);
  assert.strictEqual((await svc.status()).forward.state, 'failed');
});

test('Windows: accesses limited to services get firewall rules under the same admin prompt; stop removes exactly those', async () => {
  const { svc, calls } = service();
  await svc.saveSettings({ endpoint: 'home.example.com' });
  const p = svc.addPeer({ person: 'Lena', reach: 'services', services: [{ port: 25565 }] });
  await svc.start({ confirm: true });
  assert.strictEqual(calls.batch.length, 1, 'one prompt for tunnel and firewall');
  assert.deepStrictEqual(calls.batch[0].map((c) => c.args[0]), ['/installtunnelservice', 'advfirewall', 'advfirewall']);
  assert.deepStrictEqual(svc.load().firewall, [`name=Hostwerk VPN ${p.id} TCP`, `name=Hostwerk VPN ${p.id} UDP`]);
  svc.removePeer(p.id);
  await svc.stop({ confirm: true });
  assert.deepStrictEqual(calls.batch[1].map((c) => c.args.join(' ')), ['/uninstalltunnelservice hostwerk', `advfirewall firewall delete rule name=Hostwerk VPN ${p.id} TCP`, `advfirewall firewall delete rule name=Hostwerk VPN ${p.id} UDP`]);
  assert.deepStrictEqual(svc.load().firewall, []);
  // ohne Sammel-Abfrage (älteres Hostwerk): klare Meldung statt halber Sache
  const old = service({ noBatch: true });
  await old.svc.saveSettings({ endpoint: 'home.example.com' });
  old.svc.addPeer({ person: 'Lena', reach: 'services', services: [{ port: 80 }] });
  await assert.rejects(old.svc.start({ confirm: true }), /Hostwerk 2\.12/);
});

test('other VPNs: Tailscale devices, exit node and subnets, Headscale, ZeroTier and NetBird – read only', async () => {
  const ts = { BackendState: 'Running', Self: { HostName: 'pc', DNSName: 'pc.tail.ts.net.', TailscaleIPs: ['100.64.0.1'] }, CurrentTailnet: { Name: 'home' },
    Peer: { a: { HostName: 'phone', OS: 'android', Online: true, TailscaleIPs: ['100.64.0.2'], ExitNode: true, ExitNodeOption: true, LastSeen: '2026-10-21T10:00:00Z' }, b: { HostName: 'laptop', OS: 'windows', Online: false, TailscaleIPs: ['100.64.0.3'], LastSeen: '0001-01-01T00:00:00Z' } } };
  const f = fakeSystem({ tailscale: ts, prefs: { ControlURL: 'https://hs.example.com', AdvertiseRoutes: ['0.0.0.0/0', '::/0', '192.168.178.0/24'] }, zerotier: true, netbird: true });
  const t = await f.sys.tailscale();
  assert.deepStrictEqual(t.devices.map((d) => [d.name, d.online, d.exitNode]), [['phone', true, true], ['laptop', false, false]]);
  assert.strictEqual(t.devices[1].lastSeen, null);
  assert.strictEqual(t.exitNode, 'phone');
  assert.deepStrictEqual(t.advertises, { exitNode: true, routes: ['192.168.178.0/24'] });
  assert.deepStrictEqual([t.controlUrl, t.headscale], ['https://hs.example.com', true]);
  assert.strictEqual((await fakeSystem({ tailscale: ts, prefs: { ControlURL: 'https://controlplane.tailscale.com' } }).sys.tailscale()).headscale, false);
  const z = await f.sys.zerotier();
  assert.deepStrictEqual([z.online, z.address, z.networks[0].name, z.networks[0].ips], [true, 'abcdef0123', 'home', ['10.147.17.5/24']]);
  assert.deepStrictEqual(await fakeSystem({ zerotier: 'denied' }).sys.zerotier(), { installed: true, needsAdmin: true });
  const n = await f.sys.netbird();
  assert.deepStrictEqual([n.running, n.ip, n.peers, n.online], [true, '100.92.0.4/16', 3, 2]);
  assert.deepStrictEqual(await fakeSystem().sys.netbird(), { installed: false });
  const h = await fakeSystem({ platform: 'linux', headscale: true }).sys.headscale();
  assert.deepStrictEqual(h, { installed: true, version: '0.23.0' });
  const { svc } = service({ tailscale: ts });
  const o = await svc.others();
  assert.deepStrictEqual(Object.keys(o), ['platform', 'tailscale', 'headscale', 'zerotier', 'netbird']);
  assert.ok(f.calls.elevated.length === 0, 'reading never asks for admin rights');
});
