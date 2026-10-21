'use strict';
/* Schlüssel und Konfigurationsdateien – reine Funktionen, nichts am System.   node --test tests/ */
const test = require('node:test');
const assert = require('node:assert');
const K = require('../server/keys');
const W = require('../server/wgconf');

test('keys: X25519 like wg genkey/pubkey (RFC 7748 test vector), clamped, base64', () => {
  const priv = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex').toString('base64');
  assert.strictEqual(Buffer.from(K.publicKey(priv), 'base64').toString('hex'), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
  const kp = K.keyPair();
  assert.ok(K.isKey(kp.privateKey) && K.isKey(kp.publicKey));
  const raw = Buffer.from(kp.privateKey, 'base64');
  assert.strictEqual(raw[0] & 7, 0); assert.strictEqual(raw[31] & 128, 0); assert.strictEqual(raw[31] & 64, 64);
  assert.notStrictEqual(K.keyPair().privateKey, kp.privateKey);
  assert.ok(K.isKey(K.presharedKey()));
  assert.ok(!K.isKey('short')); assert.throws(() => K.publicKey('AAAA'));
});

test('settings: defaults, checks and the home network only on Linux', () => {
  assert.deepStrictEqual(W.settings({}, 'win32'), { port: 51820, subnet: '10.66.66.0/24', endpoint: '', dns: '', scope: 'host', lanSubnet: '', keepalive: 25, endpointMode: 'manual', autoForward: true, rotateMonths: 0, updateCheck: true });
  assert.strictEqual(W.settings({ endpoint: ' Home.Example.com ' }).endpoint, 'home.example.com');
  assert.strictEqual(W.settings({ endpoint: '[2001:db8::1]' }).endpoint, '2001:db8::1');
  assert.strictEqual(W.settings({ dns: '1.1.1.1 9.9.9.9' }).dns, '1.1.1.1, 9.9.9.9');
  const no = (s, re, p = 'linux') => assert.throws(() => W.settings(s, p), (e) => e.status === 400 && re.test(e.message));
  no({ port: 80 }, /between 1024 and 65535/);
  no({ subnet: '10.66.66.0/16' }, /10\.66\.66\.0\/24/);
  no({ subnet: '8.8.8.0/24' }, /private network/);
  no({ endpoint: 'not a host' }, /host name/);
  no({ dns: 'dns.google' }, /IP addresses/);
  no({ scope: 'lan', lanSubnet: '192.168.178.0/24' }, /needs Linux/, 'win32');
  no({ scope: 'lan', lanSubnet: 'x' }, /home network/);
  assert.strictEqual(W.settings({ scope: 'lan', lanSubnet: '192.168.178.7/24' }, 'linux').lanSubnet, '192.168.178.0/24');
  for (const ok of ['172.20.1.0/24', '192.168.50.0/24', '100.100.3.0/24']) assert.strictEqual(W.settings({ subnet: ok }).subnet, ok);
});

test('addresses: this PC is .1, accesses get the next free one', () => {
  assert.strictEqual(W.serverAddress('10.66.66.0/24'), '10.66.66.1');
  assert.strictEqual(W.nextAddress('10.66.66.0/24', []), '10.66.66.2');
  assert.strictEqual(W.nextAddress('10.66.66.0/24', ['10.66.66.2', '10.66.66.4']), '10.66.66.3');
  const all = Array.from({ length: 253 }, (_, i) => `10.66.66.${i + 2}`);
  assert.throws(() => W.nextAddress('10.66.66.0/24', all), (e) => e.status === 409);
});

test('server file: interface, one peer per enabled access, comments cannot break the file', () => {
  const s = W.settings({ endpoint: 'home.example.com' }, 'win32');
  const txt = W.serverConfig({ settings: s, privateKey: 'SERVERPRIV', platform: 'win32', peers: [
    { person: 'Lena', device: 'Handy', address: '10.66.66.2', publicKey: 'PUB1', presharedKey: 'PSK1' },
    { person: 'Tom\n[Interface]\nPrivateKey = x', device: '', address: '10.66.66.3', publicKey: 'PUB2', presharedKey: 'PSK2' },
    { person: 'Off', address: '10.66.66.4', publicKey: 'PUB3', enabled: false },
  ] });
  assert.match(txt, /\[Interface\]\nAddress = 10\.66\.66\.1\/24\nListenPort = 51820\nPrivateKey = SERVERPRIV\n/);
  assert.match(txt, /# Lena – Handy\n\[Peer\]\nPublicKey = PUB1\nPresharedKey = PSK1\nAllowedIPs = 10\.66\.66\.2\/32/);
  assert.strictEqual((txt.match(/\[Interface\]/g) || []).length, 1, 'a name cannot add a section');
  assert.ok(!txt.includes('PUB3'), 'switched-off access is left out');
  assert.ok(!txt.includes('PostUp'));
  const lan = W.serverConfig({ settings: W.settings({ scope: 'lan', lanSubnet: '192.168.178.0/24' }, 'linux'), privateKey: 'P', platform: 'linux', peers: [] });
  assert.match(lan, /PostUp = sysctl -q -w net\.ipv4\.ip_forward=1; .*MASQUERADE/);
  assert.match(lan, /PostDown = iptables -t nat -D POSTROUTING .*iptables -D FORWARD -i %i -j ACCEPT\n/, 'taken down in reverse order');
});

test('device file: endpoint, reach, DNS, keepalive – and a clear error without endpoint', () => {
  const peer = { person: 'Lena', device: 'Handy', address: '10.66.66.2' };
  const s = W.settings({ endpoint: 'home.example.com', dns: '1.1.1.1' }, 'win32');
  const txt = W.clientConfig({ settings: s, serverPublicKey: 'SPUB', peer, privateKey: 'CPRIV', presharedKey: 'PSK' });
  assert.strictEqual(txt, '# Hostwerk VPN – Lena – Handy\n[Interface]\nPrivateKey = CPRIV\nAddress = 10.66.66.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = SPUB\nPresharedKey = PSK\nEndpoint = home.example.com:51820\nAllowedIPs = 10.66.66.1/32\nPersistentKeepalive = 25\n');
  const v6 = W.clientConfig({ settings: W.settings({ endpoint: '2001:db8::1', port: 51999 }), serverPublicKey: 'S', peer, privateKey: 'C' });
  assert.match(v6, /Endpoint = \[2001:db8::1\]:51999/);
  const lan = W.clientConfig({ settings: W.settings({ endpoint: '203.0.113.5', scope: 'lan', lanSubnet: '192.168.178.0/24' }, 'linux'), serverPublicKey: 'S', peer, privateKey: 'C' });
  assert.match(lan, /AllowedIPs = 10\.66\.66\.0\/24, 192\.168\.178\.0\/24/);
  assert.throws(() => W.clientConfig({ settings: W.settings({}), serverPublicKey: 'S', peer, privateKey: 'C' }), (e) => e.status === 409 && /address from outside/.test(e.message));
});

test('file name: usable as WireGuard tunnel name', () => {
  assert.strictEqual(W.fileName({ person: 'Jörg Müßig', device: 'Laptop (Arbeit)' }), 'hw-jorg-mussig-laptop-arbeit.conf');
  assert.ok(W.fileName({ person: 'x'.repeat(80) }).length <= 33);
  assert.strictEqual(W.fileName({ person: '!!!' }), 'hw.conf');
});

test('own name through the DNS extension must be a host name; maintenance options are clamped', () => {
  assert.throws(() => W.settings({ endpointMode: 'dns', endpoint: '203.0.113.5' }), (e) => e.status === 400 && /host name of your domain/.test(e.message));
  assert.throws(() => W.settings({ endpointMode: 'dns', endpoint: '' }), /host name of your domain/);
  assert.strictEqual(W.settings({ endpointMode: 'dns', endpoint: 'VPN.example.com' }).endpoint, 'vpn.example.com');
  assert.throws(() => W.settings({ endpointMode: 'magic' }), /Unknown way/);
  assert.strictEqual(W.settings({ rotateMonths: 7 }).rotateMonths, 0);
  assert.strictEqual(W.settings({ rotateMonths: 12, autoForward: false, updateCheck: false }).rotateMonths, 12);
});

test('access options: reach, services, device type, end date – full tunnel only on Linux', () => {
  const now = 1_800_000_000_000;
  assert.deepStrictEqual(W.peerOptions({}, 'win32', {}, now), { reach: 'home', services: [], platform: 'other', expires: null });
  assert.deepStrictEqual(W.peerOptions({ reach: 'services', services: [{ port: 25565, name: 'MC' }, { port: '8080', name: 'Web\nx' }, { port: 25565 }], platform: 'android', expires: now + 1000 }, 'win32', {}, now),
    { reach: 'services', services: [{ port: 25565, name: 'MC' }, { port: 8080, name: 'Web x' }], platform: 'android', expires: now + 1000 });
  assert.throws(() => W.peerOptions({ reach: 'full' }, 'win32'), (e) => e.status === 400 && /needs Linux/.test(e.message));
  assert.strictEqual(W.peerOptions({ reach: 'full' }, 'linux').reach, 'full');
  assert.throws(() => W.peerOptions({ reach: 'services', services: [] }, 'linux'), /at least one service/);
  assert.throws(() => W.peerOptions({ reach: 'services', services: [{ port: 70000 }] }, 'linux'), /Invalid port/);
  assert.throws(() => W.peerOptions({ platform: 'toaster' }, 'linux'), /device type/);
  assert.throws(() => W.peerOptions({ expires: now - 3600000 }, 'linux', {}, now), /future/);
  // beim Ändern bleibt, was nicht mitkommt
  assert.deepStrictEqual(W.peerOptions({ expires: null }, 'linux', { reach: 'full', platform: 'ios', expires: now }, now), { reach: 'full', services: [], platform: 'ios', expires: null });
});

test('reach per access: AllowedIPs in the device file, DNS for the full tunnel', () => {
  const s = W.settings({ endpoint: 'home.example.com' }, 'linux');
  const peer = { person: 'Lena', address: '10.66.66.2' };
  assert.strictEqual(W.allowedIps(s, peer), '10.66.66.1/32');
  assert.strictEqual(W.allowedIps(s, { ...peer, reach: 'full' }), '0.0.0.0/0, ::/0');
  assert.strictEqual(W.allowedIps(W.settings({ scope: 'lan', lanSubnet: '192.168.178.0/24' }, 'linux'), { ...peer, reach: 'services' }), '10.66.66.1/32');
  const full = W.clientConfig({ settings: s, serverPublicKey: 'S', peer: { ...peer, reach: 'full' }, privateKey: 'C' });
  assert.match(full, /DNS = 1\.1\.1\.1, 9\.9\.9\.9\n/);
  assert.match(full, /AllowedIPs = 0\.0\.0\.0\/0, ::\/0/);
  const own = W.clientConfig({ settings: W.settings({ endpoint: 'h.example.com', dns: '192.168.178.1' }, 'linux'), serverPublicKey: 'S', peer: { ...peer, reach: 'full' }, privateKey: 'C' });
  assert.match(own, /DNS = 192\.168\.178\.1\n/);
});

test('Linux firewall: forwarding only when needed, services limited per access, home accesses cannot surf through home', () => {
  const s = W.settings({}, 'linux');
  assert.deepStrictEqual(W.linuxRules(s, [{ address: '10.66.66.2' }]), { up: [], down: [] });
  const r = W.linuxRules(s, [{ address: '10.66.66.2', reach: 'full' }, { address: '10.66.66.3' }, { address: '10.66.66.4', reach: 'services', services: [{ port: 8080 }, { port: 25565 }] }, { address: '10.66.66.5', reach: 'full', enabled: false }]);
  assert.strictEqual(r.up[0], 'sysctl -q -w net.ipv4.ip_forward=1');
  assert.ok(r.up.includes('iptables -A FORWARD -i %i -s 10.66.66.3 -j DROP'), 'home access: no forwarding');
  assert.ok(r.up.includes('iptables -A INPUT -i %i -s 10.66.66.4 -p tcp -m multiport --dports 8080,25565 -j ACCEPT'));
  assert.ok(r.up.includes('iptables -A INPUT -i %i -s 10.66.66.4 -j DROP'));
  assert.ok(r.up.indexOf('iptables -A FORWARD -i %i -s 10.66.66.3 -j DROP') < r.up.indexOf('iptables -A FORWARD -i %i -j ACCEPT'), 'drops come before the general accept');
  assert.ok(r.up.some((c) => /MASQUERADE/.test(c)));
  assert.ok(!r.up.join(' ').includes('10.66.66.5'), 'switched-off access gets no rules');
  assert.strictEqual(r.down.length, r.up.length - 1);
  assert.ok(r.down.every((c) => / -D /.test(c)));
  assert.strictEqual(r.down[0], r.up[r.up.length - 1].replace(' -A ', ' -D '));
  const lan = W.linuxRules(W.settings({ scope: 'lan', lanSubnet: '192.168.178.0/24' }, 'linux'), [{ address: '10.66.66.2' }]);
  assert.ok(lan.up.includes('iptables -A FORWARD -i %i -s 10.66.66.2 ! -d 192.168.178.0/24 -j DROP'), 'home network yes, internet no');
  const conf = W.serverConfig({ settings: s, privateKey: 'P', platform: 'linux', peers: [{ person: 'A', address: '10.66.66.2', publicKey: 'X', reach: 'full' }] });
  assert.match(conf, /PostUp = sysctl .*MASQUERADE\nPostDown = iptables -t nat -D POSTROUTING/);
  assert.ok(!W.serverConfig({ settings: s, privateKey: 'P', platform: 'win32', peers: [{ person: 'A', address: '10.66.66.2', publicKey: 'X', reach: 'services', services: [{ port: 80 }] }] }).includes('PostUp'));
});

test('Windows firewall: block every other port, only from the access address; locked accesses are left out', () => {
  assert.strictEqual(W.complementRanges([80, 443, 25565]), '1-79,81-442,444-25564,25566-65535');
  assert.strictEqual(W.complementRanges([1, 2, 65535]), '3-65534');
  assert.strictEqual(W.complementRanges([2]), '1,3-65535');
  const peers = [{ id: 'a1', address: '10.66.66.2', reach: 'services', services: [{ port: 25565 }] }, { id: 'b2', address: '10.66.66.3' }, { id: 'c3', address: '10.66.66.4', reach: 'services', services: [{ port: 80 }], lock: { reason: 'manual' } }];
  const add = W.winFirewall(peers, 'add');
  assert.strictEqual(add.length, 2);
  assert.deepStrictEqual(add[0], { cmd: 'netsh', args: ['advfirewall', 'firewall', 'add', 'rule', 'name=Hostwerk VPN a1 TCP', 'dir=in', 'action=block', 'protocol=TCP', 'localport=1-25564,25566-65535', 'remoteip=10.66.66.2', 'profile=any'] });
  assert.deepStrictEqual(W.winFirewall(peers, 'delete')[1].args, ['advfirewall', 'firewall', 'delete', 'rule', 'name=Hostwerk VPN a1 UDP']);
  const conf = W.serverConfig({ settings: W.settings({}, 'win32'), privateKey: 'P', platform: 'win32', peers: peers.map((p) => ({ ...p, person: p.id, publicKey: `PUB-${p.id}` })) });
  assert.ok(!conf.includes('PUB-c3'), 'locked access is not in the tunnel');
});
