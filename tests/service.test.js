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
function fakeSystem({ platform = 'win32', installed = true, running = false, service = false, elevatedCode = 0, tailscale = null, dump = '' } = {}) {
  const calls = { run: [], elevated: [] };
  const st = { running, service };
  const files = new Set(installed ? (platform === 'win32' ? [WG_EXE, WG_CLI] : []) : []);
  if (tailscale && platform === 'win32') files.add('C:\\Program Files\\Tailscale\\tailscale.exe');
  const sys = new WgSystem({
    platform,
    env: { ProgramFiles: 'C:\\Program Files' },
    exists: (p) => files.has(p) || (p === '/sys/class/net/hostwerk' && st.running),
    which: async (n) => (platform === 'linux' && installed && ['wg', 'wg-quick'].includes(n) ? `/usr/bin/${n}` : n === 'tailscale' && tailscale ? '/usr/bin/tailscale' : null),
    run: async (cmd, args) => {
      calls.run.push([cmd, ...args]);
      if (cmd === 'sc') return st.service || st.running ? { code: 0, stdout: `SERVICE_NAME: WireGuardTunnel$hostwerk\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : ${st.running ? '4  RUNNING' : '1  STOPPED'}\n` } : { code: 1060, stdout: '[SC] EnumQueryServicesStatus:OpenService FAILED 1060' };
      if (/wg(\.exe)?$/.test(cmd)) return dump ? { code: 0, stdout: dump } : { code: 1, stdout: '' };
      if (/tailscale/.test(cmd)) return { code: 0, stdout: JSON.stringify(tailscale) };
      return { code: 1, stdout: '' };
    },
    elevated: async (cmd, args) => {
      calls.elevated.push([cmd, ...args]);
      if (elevatedCode === 0) { if (args[0] === '/installtunnelservice' || args[0] === 'up') st.running = true; else st.running = false; }
      return elevatedCode;
    },
  });
  return { sys, calls, st };
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
  assert.deepStrictEqual(await f.sys.handshakes(det), { PEER1: { endpoint: '198.51.100.7:4242', lastHandshake: 1760000000000, rx: 1200, tx: 3400 }, PEER2: { endpoint: null, lastHandshake: null, rx: 0, tx: 0 } });
  assert.deepStrictEqual(await fakeSystem().sys.tunnel(det), { running: false, service: false });
  assert.deepStrictEqual(await fakeSystem({ service: true }).sys.tunnel(det), { running: false, service: true });
  assert.deepStrictEqual(await fakeSystem({ running: true }).sys.handshakes(det), {}, 'no rights → no handshakes, no error');
  const l = fakeSystem({ platform: 'linux', running: true });
  assert.strictEqual((await l.sys.tunnel(await l.sys.detect())).running, true);
});

test('tailscale: read-only status', async () => {
  const ts = { BackendState: 'Running', Self: { HostName: 'pc', DNSName: 'pc.tail1234.ts.net.', TailscaleIPs: ['100.101.102.103'] }, CurrentTailnet: { Name: 'me@example.com' }, Peer: { a: { Online: true }, b: { Online: false } } };
  const f = fakeSystem({ tailscale: ts });
  assert.deepStrictEqual(await f.sys.tailscale(), { installed: true, running: true, state: 'Running', name: 'pc', dnsName: 'pc.tail1234.ts.net', ips: ['100.101.102.103'], tailnet: 'me@example.com', peers: 2, online: 1 });
  assert.deepStrictEqual(f.calls.run.at(-1).slice(1), ['status', '--json']);
  assert.deepStrictEqual(await fakeSystem().sys.tailscale(), { installed: false });
  assert.strictEqual((await fakeSystem({ platform: 'linux', tailscale: { BackendState: 'NeedsLogin' } }).sys.tailscale()).running, false);
});

function service(opts = {}, ctx = {}) {
  const f = fakeSystem(opts);
  const dir = tmp();
  const svc = new VpnService({ dir, secrets, system: f.sys, qr: async (t) => `<svg data-len="${t.length}"/>`, ctx, platform: opts.platform || 'win32' });
  return { svc, dir, ...f };
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
    t: (s) => s, broadcast: () => {}, log: () => {},
  };
  const mod = require('../server/index');
  mod.activate(host);
  assert.ok(provided.vpn instanceof VpnService);
  for (const k of ['GET /vpn', 'PUT /vpn/settings', 'GET /vpn/endpoint-suggestion', 'GET /vpn/members', 'POST /vpn/peers', 'PUT /vpn/peers/:id', 'POST /vpn/peers/:id/rekey', 'DELETE /vpn/peers/:id', 'GET /vpn/peers/:id/config', 'POST /vpn/start', 'POST /vpn/stop', 'POST /vpn/forward']) assert.ok(routes[k], k);
  await assert.rejects(routes['POST /vpn/start']({ body: {} }, {}), (e) => e.status === 428);
  await assert.rejects(routes['DELETE /vpn/peers/:id']({ params: { id: 'x' } }, {}), (e) => e.status === 404);
  assert.strictEqual(elevatedCalls, 0);
  mod.deactivate();
});
