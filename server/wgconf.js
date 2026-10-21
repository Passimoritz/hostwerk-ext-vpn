'use strict';
/*
 * WireGuard-Konfiguration: Einstellungen prüfen, Adressen im VPN vergeben, Server- und Gerätedatei schreiben.
 * Reine Funktionen ohne Dateien und Programme – dadurch vollständig testbar.
 *
 *   Netz      IPv4 /24, z. B. 10.66.66.0/24 – dieser PC ist .1, Zugänge bekommen .2 … .254
 *   Reichweite host = nur dieser PC (geht überall, ohne Weiterleitung)
 *              lan  = dieser PC und das Heimnetz dahinter (nur Linux: Weiterleitung + NAT per PostUp)
 *   Je Zugang  home     = wie oben (Standard, „nur zu Hause“ – der übrige Verkehr des Geräts geht wie immer)
 *              full     = der ganze Internetverkehr des Geräts läuft über zu Hause (nur Linux: Weiterleitung + NAT)
 *              services = nur bestimmte Dienste auf diesem PC (Ports) – Linux per iptables, Windows per Firewall-Regel
 *   Adresse    manual = von Hand · dyndns = DynDNS-Name der Router-Erweiterung · dns = eigener Name, den das VPN über die
 *              DNS-Erweiterung auf die öffentliche IP hält
 */
const net = require('net');

const IFACE = 'hostwerk'; // Name des Tunnels (Windows-Dienst WireGuardTunnel$hostwerk, Linux-Schnittstelle hostwerk)
const DEFAULTS = {
  port: 51820, subnet: '10.66.66.0/24', endpoint: '', dns: '', scope: 'host', lanSubnet: '', keepalive: 25,
  endpointMode: 'manual', autoForward: true, rotateMonths: 0, updateCheck: true,
};
const PLATFORMS = ['android', 'ios', 'windows', 'macos', 'linux', 'other'];
const REACH = ['home', 'full', 'services'];
/** DNS für Geräte mit „alles über zu Hause“, wenn keiner eingestellt ist – sonst fragt das Gerät z. B. den DNS seines Mobilfunks über die Heimleitung, und der antwortet nicht */
const FULL_DNS = '1.1.1.1, 9.9.9.9';

const bad = (text) => Object.assign(new Error(text), { status: 400 });
const ipToInt = (ip) => ip.split('.').reduce((n, x) => (n << 8) + Number(x), 0) >>> 0;
const intToIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');

/** "10.66.66.0/24" → { base: '10.66.66', prefix: 24 } – nur private /24-Netze. */
function parseSubnet(s) {
  const m = /^(\d+\.\d+\.\d+)\.0\/24$/.exec(String(s || '').trim());
  if (!m || !net.isIPv4(`${m[1]}.0`)) throw bad('The VPN network must look like 10.66.66.0/24.');
  const n = ipToInt(`${m[1]}.0`);
  const priv = (n >>> 24) === 10 || (n >>> 20) === (172 << 4 | 1) || (n >>> 16) === (192 << 8 | 168) || (n >>> 22) === (100 << 2 | 1);
  if (!priv) throw bad('Use a private network (10.x, 172.16–31.x, 192.168.x or 100.64–127.x).');
  return { base: m[1], prefix: 24 };
}

/** Beliebiges IPv4-Netz "192.168.178.0/24" prüfen (für das Heimnetz). */
function checkCidr(s) {
  const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(String(s || '').trim());
  if (!m || !net.isIPv4(m[1]) || Number(m[2]) > 32) throw bad('The home network must look like 192.168.178.0/24.');
  const p = Number(m[2]);
  const n = ipToInt(m[1]) & (p ? (~0 << (32 - p)) >>> 0 : 0);
  return `${intToIp(n >>> 0)}/${p}`;
}

const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/i;
/** Endpunkt: Name oder Adresse, unter der Geräte diesen PC aus dem Internet erreichen. */
function checkEndpoint(s) {
  const e = String(s || '').trim().replace(/^\[|\]$/g, '');
  if (!e) return '';
  if (net.isIP(e)) return e;
  if (!HOST_RE.test(e)) throw bad('The address from outside must be a host name (e.g. home.example.com) or an IP address.');
  return e.toLowerCase();
}
const endpointText = (host, port) => (net.isIPv6(host) ? `[${host}]:${port}` : `${host}:${port}`);

/** Einstellungen prüfen und mit Standardwerten auffüllen. platform: 'win32' | 'linux' | … */
function settings(input = {}, platform = process.platform) {
  const s = { ...DEFAULTS, ...input };
  const port = Number(s.port);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw bad('The port must be between 1024 and 65535.');
  parseSubnet(s.subnet);
  const dns = String(s.dns || '').split(/[\s,]+/).filter(Boolean);
  for (const d of dns) if (!net.isIP(d)) throw bad('DNS servers must be IP addresses, e.g. 1.1.1.1.');
  if (!['host', 'lan'].includes(s.scope)) throw bad('Unknown reach.');
  if (s.scope === 'lan' && platform !== 'linux') throw bad('Reaching the home network through the VPN needs Linux (forwarding with wg-quick). On Windows only this PC is reachable.');
  if (!['manual', 'dyndns', 'dns'].includes(s.endpointMode)) throw bad('Unknown way to find this PC.');
  const endpoint = checkEndpoint(s.endpoint);
  // Eigener Name über die DNS-Erweiterung: muss ein Name sein (keine IP) – das VPN hält dessen A/AAAA-Eintrag aktuell
  if (s.endpointMode === 'dns' && (!endpoint || net.isIP(endpoint))) throw bad('For your own name enter a host name of your domain, e.g. vpn.example.com.');
  const keepalive = Number(s.keepalive);
  const rotate = Number(s.rotateMonths);
  return {
    port, subnet: String(s.subnet).trim(), endpoint, dns: dns.join(', '), scope: s.scope,
    lanSubnet: s.scope === 'lan' ? checkCidr(s.lanSubnet) : (s.lanSubnet ? checkCidr(s.lanSubnet) : ''),
    keepalive: Number.isInteger(keepalive) && keepalive >= 0 && keepalive <= 600 ? keepalive : DEFAULTS.keepalive,
    endpointMode: s.endpointMode, autoForward: s.autoForward !== false, rotateMonths: [0, 6, 12, 24].includes(rotate) ? rotate : 0, updateCheck: s.updateCheck !== false,
  };
}

/** Kann dieses System „ganzer Verkehr über zu Hause“ (Weiterleitung + NAT)? Nur Linux mit wg-quick. */
const canFull = (platform) => platform === 'linux';

/**
 * Optionen eines Zugangs prüfen: { reach, services: [{ port, name }], platform, expires }.
 * old = bisherige Werte (beim Ändern), now = Zeit (Tests).
 */
function peerOptions(b = {}, platform = process.platform, old = {}, now = Date.now()) {
  const reach = b.reach !== undefined ? String(b.reach) : (old.reach || 'home');
  if (!REACH.includes(reach)) throw bad('Unknown reach.');
  if (reach === 'full' && !canFull(platform)) throw bad('Sending all internet traffic through home needs Linux (forwarding and NAT). On Windows choose “Home only”.');
  let services = b.services !== undefined ? b.services : (old.services || []);
  if (!Array.isArray(services)) throw bad('Choose the services this access may use.');
  services = services.slice(0, 30).map((x) => ({ port: Number(x && x.port), name: String((x && x.name) || '').replace(/[\r\n]+/g, ' ').trim().slice(0, 60) }));
  for (const x of services) if (!Number.isInteger(x.port) || x.port < 1 || x.port > 65535) throw bad('Invalid port');
  services = services.filter((x, i) => services.findIndex((y) => y.port === x.port) === i);
  if (reach === 'services' && !services.length) throw bad('Choose at least one service for this access.');
  const plat = b.platform !== undefined ? String(b.platform) : (old.platform || 'other');
  if (!PLATFORMS.includes(plat)) throw bad('Unknown device type.');
  let expires = b.expires !== undefined ? b.expires : (old.expires === undefined ? null : old.expires);
  if (expires !== null && expires !== '' && expires !== 0) {
    expires = Number(expires);
    if (!Number.isFinite(expires) || expires < now - 60000) throw bad('The end date must be in the future.');
  } else expires = null;
  return { reach, services: reach === 'services' ? services : [], platform: plat, expires };
}

const serverAddress = (subnet) => `${parseSubnet(subnet).base}.1`;

/** Nächste freie Adresse im Netz (.2 … .254). */
function nextAddress(subnet, used) {
  const { base } = parseSubnet(subnet);
  const taken = new Set(used || []);
  for (let i = 2; i <= 254; i++) { const ip = `${base}.${i}`; if (!taken.has(ip)) return ip; }
  throw Object.assign(new Error('The VPN network is full (253 accesses).'), { status: 409 });
}

/** Zeile für Kommentare in der Datei: keine Zeilenumbrüche, nichts, was WireGuard als Abschnitt lesen könnte. */
const comment = (s) => String(s || '').replace(/[\r\n[\]=]+/g, ' ').trim().slice(0, 80);
/** Ist der Zugang aktiv? (an, nicht gesperrt) */
const active = (p) => p.enabled !== false && !p.lock;
const reachOf = (p) => (REACH.includes(p.reach) ? p.reach : 'home');
const portList = (p) => (p.services || []).map((x) => x.port).filter((n) => Number.isInteger(n)).sort((a, b) => a - b);

/**
 * Firewall-Regeln für Linux (iptables, in PostUp/PostDown der Server-Datei) – nur, wo nötig:
 *   - Weiterleitung + NAT, wenn das Heimnetz erreichbar ist oder ein Zugang „alles über zu Hause“ hat
 *   - je Zugang „nur bestimmte Dienste“: nur diese Ports auf diesem PC, keine Weiterleitung
 *   - ist Weiterleitung an, dürfen „nur zu Hause“-Zugänge trotzdem nicht ins Internet bzw. nur ins Heimnetz
 *     (sonst könnte ein Gerät seine AllowedIPs selbst erweitern und durch zu Hause surfen)
 * → { up: [...], down: [...] } (Befehle; %i = Schnittstelle)
 */
function linuxRules(s, peers) {
  const on = peers.filter(active);
  const forward = s.scope === 'lan' || on.some((p) => reachOf(p) === 'full');
  const up = [];
  for (const p of on) {
    const r = reachOf(p);
    if (r === 'services') {
      const ports = portList(p).join(',');
      up.push(`iptables -A INPUT -i %i -s ${p.address} -m state --state RELATED,ESTABLISHED -j ACCEPT`);
      for (const proto of ['tcp', 'udp']) up.push(`iptables -A INPUT -i %i -s ${p.address} -p ${proto} -m multiport --dports ${ports} -j ACCEPT`);
      up.push(`iptables -A INPUT -i %i -s ${p.address} -j DROP`);
      if (forward) up.push(`iptables -A FORWARD -i %i -s ${p.address} -j DROP`);
    } else if (r === 'home' && forward) {
      if (s.scope === 'lan' && s.lanSubnet) up.push(`iptables -A FORWARD -i %i -s ${p.address} ! -d ${s.lanSubnet} -j DROP`);
      else up.push(`iptables -A FORWARD -i %i -s ${p.address} -j DROP`);
    }
  }
  if (forward) {
    up.unshift('sysctl -q -w net.ipv4.ip_forward=1');
    up.push('iptables -A FORWARD -i %i -j ACCEPT', 'iptables -A FORWARD -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT', `iptables -t nat -A POSTROUTING -s ${s.subnet} ! -o %i -j MASQUERADE`);
  }
  // Abbauen in umgekehrter Reihenfolge, gleiche Regeln mit -D (sysctl bleibt – andere Dienste brauchen es evtl.)
  const down = up.filter((c) => c.startsWith('iptables')).map((c) => c.replace(/ -A /, ' -D ')).reverse();
  return { up, down };
}

/**
 * Windows: Zugänge „nur bestimmte Dienste“ über die Windows-Firewall. Sperr-Regeln gehen dort vor Erlauben-Regeln –
 * deshalb sperrt je Zugang eine Regel alle ANDEREN Ports (Bereiche um die erlaubten herum), nur von seiner VPN-Adresse.
 * Regelname „Hostwerk VPN <id> TCP|UDP“ – Stoppen entfernt genau diese.
 * → [{ cmd: 'netsh', args }] (mode: 'add' | 'delete')
 */
function complementRanges(ports) {
  const out = []; let from = 1;
  for (const p of [...new Set(ports)].sort((a, b) => a - b)) { if (p > from) out.push(p - 1 === from ? `${from}` : `${from}-${p - 1}`); from = p + 1; }
  if (from <= 65535) out.push(from === 65535 ? '65535' : `${from}-65535`);
  return out.join(',');
}
const winRuleName = (p, proto) => `Hostwerk VPN ${p.id} ${proto}`;
function winFirewall(peers, mode = 'add') {
  const out = [];
  for (const p of peers.filter((x) => active(x) && reachOf(x) === 'services')) {
    for (const proto of ['TCP', 'UDP']) {
      const name = `name=${winRuleName(p, proto)}`;
      if (mode === 'delete') { out.push({ cmd: 'netsh', args: ['advfirewall', 'firewall', 'delete', 'rule', name] }); continue; }
      out.push({ cmd: 'netsh', args: ['advfirewall', 'firewall', 'add', 'rule', name, 'dir=in', 'action=block', `protocol=${proto}`, `localport=${complementRanges(portList(p))}`, `remoteip=${p.address}`, 'profile=any'] });
    }
  }
  return out;
}

/**
 * Datei für diesen PC. peers: [{ person, device, address, publicKey, presharedKey, enabled, lock, reach, services }]
 * (Schlüssel im Klartext).
 */
function serverConfig({ settings: s, privateKey, peers, platform = process.platform }) {
  const lines = [
    '# Hostwerk – VPN access. Written by Hostwerk; changes here are overwritten.',
    '[Interface]',
    `Address = ${serverAddress(s.subnet)}/24`,
    `ListenPort = ${s.port}`,
    `PrivateKey = ${privateKey}`,
  ];
  if (platform === 'linux') {
    const r = linuxRules(s, peers);
    if (r.up.length) lines.push(`PostUp = ${r.up.join('; ')}`);
    if (r.down.length) lines.push(`PostDown = ${r.down.join('; ')}`);
  }
  for (const p of peers.filter(active)) {
    lines.push('', `# ${comment(p.person)}${p.device ? ` – ${comment(p.device)}` : ''}`, '[Peer]', `PublicKey = ${p.publicKey}`);
    if (p.presharedKey) lines.push(`PresharedKey = ${p.presharedKey}`);
    lines.push(`AllowedIPs = ${p.address}/32`);
  }
  return `${lines.join('\n')}\n`;
}

/**
 * Was ein Gerät über das VPN schickt (AllowedIPs in seiner Datei). „full“ nimmt auch ::/0 – im Tunnel gibt es kein IPv6,
 * so läuft IPv6 nicht an zu Hause vorbei ins Netz (kein Leck); Apps fallen dann auf IPv4 zurück.
 */
function allowedIps(s, peer = {}) {
  const r = reachOf(peer);
  if (r === 'full') return '0.0.0.0/0, ::/0';
  if (r === 'services') return `${serverAddress(s.subnet)}/32`;
  const out = [`${serverAddress(s.subnet)}/32`];
  if (s.scope === 'lan') out.splice(0, 1, s.subnet, s.lanSubnet);
  return out.filter(Boolean).join(', ');
}

/** Datei für ein Gerät (zum Herunterladen oder als QR-Code). */
function clientConfig({ settings: s, serverPublicKey, peer, privateKey, presharedKey }) {
  if (!s.endpoint) throw Object.assign(new Error('Enter the address from outside first (settings) – devices need it to find this PC.'), { status: 409 });
  const lines = [
    `# Hostwerk VPN – ${comment(peer.person)}${peer.device ? ` – ${comment(peer.device)}` : ''}`,
    '[Interface]',
    `PrivateKey = ${privateKey}`,
    `Address = ${peer.address}/32`,
  ];
  const dns = s.dns || (reachOf(peer) === 'full' ? FULL_DNS : '');
  if (dns) lines.push(`DNS = ${dns}`);
  lines.push('', '[Peer]', `PublicKey = ${serverPublicKey}`);
  if (presharedKey) lines.push(`PresharedKey = ${presharedKey}`);
  lines.push(`Endpoint = ${endpointText(s.endpoint, s.port)}`, `AllowedIPs = ${allowedIps(s, peer)}`);
  if (s.keepalive) lines.push(`PersistentKeepalive = ${s.keepalive}`);
  return `${lines.join('\n')}\n`;
}

/** Dateiname für die Geräte-Konfiguration (WireGuard nimmt ihn als Tunnelnamen: höchstens 32 Zeichen, a–z 0–9 _ = + . -). */
function fileName(peer) {
  const base = `hw-${peer.person}${peer.device ? `-${peer.device}` : ''}`.toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/ß/g, 'ss').replace(/[^a-z0-9_=+.-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  return `${base.slice(0, 28) || 'hostwerk'}.conf`;
}

module.exports = {
  IFACE, DEFAULTS, PLATFORMS, REACH, FULL_DNS, settings, peerOptions, canFull, parseSubnet, checkCidr, checkEndpoint, serverAddress, nextAddress,
  serverConfig, clientConfig, allowedIps, fileName, endpointText, linuxRules, winFirewall, complementRanges, active, reachOf,
};
