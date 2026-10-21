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
  assert.deepStrictEqual(W.settings({}, 'win32'), { port: 51820, subnet: '10.66.66.0/24', endpoint: '', dns: '', scope: 'host', lanSubnet: '', keepalive: 25 });
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
  assert.match(lan, /PostDown = iptables -D FORWARD/);
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
