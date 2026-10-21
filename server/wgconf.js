'use strict';
/*
 * WireGuard-Konfiguration: Einstellungen prüfen, Adressen im VPN vergeben, Server- und Gerätedatei schreiben.
 * Reine Funktionen ohne Dateien und Programme – dadurch vollständig testbar.
 *
 *   Netz      IPv4 /24, z. B. 10.66.66.0/24 – dieser PC ist .1, Zugänge bekommen .2 … .254
 *   Reichweite host = nur dieser PC (geht überall, ohne Weiterleitung)
 *              lan  = dieser PC und das Heimnetz dahinter (nur Linux: Weiterleitung + NAT per PostUp)
 */
const net = require('net');

const IFACE = 'hostwerk'; // Name des Tunnels (Windows-Dienst WireGuardTunnel$hostwerk, Linux-Schnittstelle hostwerk)
const DEFAULTS = { port: 51820, subnet: '10.66.66.0/24', endpoint: '', dns: '', scope: 'host', lanSubnet: '', keepalive: 25 };

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

/** Endpunkt: Name oder Adresse, unter der Geräte diesen PC aus dem Internet erreichen. */
function checkEndpoint(s) {
  const e = String(s || '').trim().replace(/^\[|\]$/g, '');
  if (!e) return '';
  if (net.isIP(e)) return e;
  if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/i.test(e)) throw bad('The address from outside must be a host name (e.g. home.example.com) or an IP address.');
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
  const keepalive = Number(s.keepalive);
  return {
    port, subnet: String(s.subnet).trim(), endpoint: checkEndpoint(s.endpoint), dns: dns.join(', '), scope: s.scope,
    lanSubnet: s.scope === 'lan' ? checkCidr(s.lanSubnet) : (s.lanSubnet ? checkCidr(s.lanSubnet) : ''),
    keepalive: Number.isInteger(keepalive) && keepalive >= 0 && keepalive <= 600 ? keepalive : DEFAULTS.keepalive,
  };
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

/**
 * Datei für diesen PC. peers: [{ person, device, address, publicKey, presharedKey, enabled }] (Schlüssel im Klartext).
 */
function serverConfig({ settings: s, privateKey, peers, platform = process.platform }) {
  const lines = [
    '# Hostwerk – VPN access. Written by Hostwerk; changes here are overwritten.',
    '[Interface]',
    `Address = ${serverAddress(s.subnet)}/24`,
    `ListenPort = ${s.port}`,
    `PrivateKey = ${privateKey}`,
  ];
  if (s.scope === 'lan' && platform === 'linux') {
    lines.push(
      `PostUp = sysctl -q -w net.ipv4.ip_forward=1; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s ${s.subnet} ! -o %i -j MASQUERADE`,
      `PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s ${s.subnet} ! -o %i -j MASQUERADE`,
    );
  }
  for (const p of peers.filter((x) => x.enabled !== false)) {
    lines.push('', `# ${comment(p.person)}${p.device ? ` – ${comment(p.device)}` : ''}`, '[Peer]', `PublicKey = ${p.publicKey}`);
    if (p.presharedKey) lines.push(`PresharedKey = ${p.presharedKey}`);
    lines.push(`AllowedIPs = ${p.address}/32`);
  }
  return `${lines.join('\n')}\n`;
}

/** Was ein Gerät über das VPN erreicht. */
function allowedIps(s) {
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
  if (s.dns) lines.push(`DNS = ${s.dns}`);
  lines.push('', '[Peer]', `PublicKey = ${serverPublicKey}`);
  if (presharedKey) lines.push(`PresharedKey = ${presharedKey}`);
  lines.push(`Endpoint = ${endpointText(s.endpoint, s.port)}`, `AllowedIPs = ${allowedIps(s)}`);
  if (s.keepalive) lines.push(`PersistentKeepalive = ${s.keepalive}`);
  return `${lines.join('\n')}\n`;
}

/** Dateiname für die Geräte-Konfiguration (WireGuard nimmt ihn als Tunnelnamen: höchstens 32 Zeichen, a–z 0–9 _ = + . -). */
function fileName(peer) {
  const base = `hw-${peer.person}${peer.device ? `-${peer.device}` : ''}`.toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/ß/g, 'ss').replace(/[^a-z0-9_=+.-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  return `${base.slice(0, 28) || 'hostwerk'}.conf`;
}

module.exports = { IFACE, DEFAULTS, settings, parseSubnet, checkCidr, checkEndpoint, serverAddress, nextAddress, serverConfig, clientConfig, allowedIps, fileName, endpointText };
