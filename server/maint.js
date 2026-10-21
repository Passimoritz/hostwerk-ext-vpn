'use strict';
/*
 * Wartung ohne Zutun – reine Funktionen (die Abläufe stehen in service.js, tick()):
 *   - abgelaufene Zugänge sperren, fällige Schlüssel-Erneuerung erkennen (nur Hinweis – neue Schlüssel heißt neue Datei
 *     fürs Gerät, das kann Hostwerk nicht für dich erledigen)
 *   - neueste WireGuard-Version für Windows aus der offiziellen Quelle lesen (download.wireguard.com, dieselbe Liste,
 *     die WireGuards eigener Updater nutzt) und mit der installierten vergleichen
 *   - Gesundheit zu einer Liste von Befunden bündeln: [{ id, level: 'err' | 'warn' | 'info', title, text, action }]
 * Texte sind Englisch, Deutsch kommt aus locales/de.json (host.t bzw. t() in der Oberfläche).
 */

const DAY = 24 * 3600000;
const MONTH = 30 * DAY;
/** Offizielle Liste der aktuellen Windows-Installer (signiert; wir lesen nur die Versionsnummer, laden nichts herunter) */
const WIN_LATEST_URL = 'https://download.wireguard.com/windows-client/latest.sig';

/** "…  wireguard-amd64-0.5.3.msi" → '0.5.3' (höchste genannte Version) */
function parseLatestWindows(text) {
  let best = null;
  for (const m of String(text || '').matchAll(/wireguard-(?:amd64|x86|arm64|arm)-(\d+\.\d+(?:\.\d+)*)\.msi/g)) if (!best || newer(m[1], best)) best = m[1];
  return best;
}

/** Ist a neuer als b? ('0.5.10' > '0.5.3') */
function newer(a, b) {
  const x = String(a || '').split('.').map(Number); const y = String(b || '').split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d > 0; }
  return false;
}

/** Zugänge, deren Ablaufdatum vorbei ist und die noch nicht gesperrt sind. */
const expiredPeers = (peers, now = Date.now()) => (peers || []).filter((p) => p.expires && p.expires <= now && !p.lock);

/** Zugänge, deren Schlüssel älter als `months` Monate sind (0 = aus). */
const rotationDue = (peers, months, now = Date.now()) => (months ? (peers || []).filter((p) => p.enabled !== false && !p.lock && now - (p.keyAt || p.created || now) > months * MONTH) : []);

/**
 * Befunde aus dem Zustand. x = {
 *   installed, running, wantRunning, startedAt, peers, settings, needsRestart,
 *   forward: { state: 'ok' | 'missing' | 'failed' | 'none', error }, net: { cgnat, dslite, v6 },
 *   endpointCheck: { ipChanged, publicIp }, dns: { ok, error }, update: { installed, latest }, now
 * }
 */
function assess(x) {
  const now = x.now || Date.now();
  const out = [];
  const add = (id, level, title, text, action = null) => out.push({ id, level, title, text, action });
  const active = (x.peers || []).filter((p) => p.enabled !== false && !p.lock);
  if (x.installed && x.wantRunning && !x.running) add('down', 'err', 'The VPN is not running', 'It was started, but the tunnel is off now – start it again.', 'start');
  if (active.length && !x.settings.endpoint) add('endpoint', 'warn', 'Address from outside is missing', 'Devices need a name or IP address to find this PC.', 'settings');
  if (x.settings.endpoint && x.endpointCheck && x.endpointCheck.ipChanged) add('ip-changed', 'warn', 'Your public IP has changed', 'The devices still have the old address. Use a name (DynDNS or your domain) instead – then this never happens again.', 'settings');
  if (x.dns && x.dns.error) add('dns', 'warn', 'The name could not be updated', x.dns.error, 'settings');
  if (x.net && x.net.cgnat && !x.net.v6) add('cgnat', 'warn', 'Your connection cannot be reached from outside', 'No own public IPv4 (carrier NAT) and no IPv6 – forwardings do not help here. Tailscale, ZeroTier or NetBird work without them.', 'others');
  else if (x.net && (x.net.dslite || x.net.cgnat)) add('dslite', 'info', 'Reachable over IPv6 only', 'Your connection has no own public IPv4. Devices reach this PC over IPv6 – most mobile networks have it. Use a name with an IPv6 entry as address from outside.', 'settings');
  if (x.running && x.forward && x.forward.state === 'failed') add('forward', 'warn', 'The router did not forward the port', x.forward.error || 'Forward the UDP port in the router by hand.', 'forward');
  if (x.running && x.needsRestart) add('restart', 'info', 'Restart needed', 'Accesses or settings changed while the tunnel was running.', 'restart');
  if (x.running && x.startedAt && now - x.startedAt > DAY && active.length && !active.some((p) => p.lastSeen && p.lastSeen > x.startedAt)) add('silent', 'info', 'No device has connected yet', 'Since the start no device has connected for a day – check the address from outside and the port forwarding.', 'check');
  if (x.update && x.update.latest && x.update.installed && newer(x.update.latest, x.update.installed)) add('update', 'info', 'WireGuard update available', `${x.update.installed} → ${x.update.latest}`, 'update');
  for (const p of rotationDue(x.peers, x.settings.rotateMonths, now).slice(0, 5)) add(`rotate-${p.id}`, 'info', 'New keys are due', p.device ? `${p.person} – ${p.device}` : p.person, 'rekey');
  return out;
}

/** Neue Befunde (die beim letzten Mal noch nicht da waren) – nur die werden gemeldet, gebündelt in EINER Nachricht. */
const fresh = (issues, before) => issues.filter((i) => i.level !== 'info' && !(before || []).includes(i.id));

module.exports = { DAY, MONTH, WIN_LATEST_URL, parseLatestWindows, newer, expiredPeers, rotationDue, assess, fresh };
