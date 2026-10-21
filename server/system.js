'use strict';
/*
 * WireGuard und Tailscale auf diesem Rechner: installiert? läuft der Tunnel? starten/stoppen.
 *
 * Alles, was das System berührt, kommt von außen herein (run, elevated, exists) – die Tests bilden es nach, beim
 * Entwickeln wird nichts gestartet und keine Netzwerk-Einstellung angefasst.
 *   run(cmd, args)       → Promise<{ code, stdout }>   normales Programm (nur lesend: sc query, wg show, tailscale status)
 *   elevated(cmd, args)  → Promise<exitCode>           mit Administrator-Rechten (Windows: UAC, Linux: pkexec)
 *   exists(path)         → boolean
 *
 * Windows: Tunnel als Dienst "WireGuardTunnel$hostwerk" (wireguard.exe /installtunnelservice <datei>), Linux: wg-quick.
 * Tailscale wird nur gelesen (tailscale status --json) – Hostwerk ändert dort nichts.
 */
const path = require('path');
const { IFACE } = require('./wgconf');

class WgSystem {
  constructor({ platform = process.platform, env = process.env, run, elevated, exists, which }) {
    this.platform = platform; this.env = env; this.run = run; this.elevated = elevated; this.exists = exists; this.which = which || (async () => null);
  }
  get win() { return this.platform === 'win32'; }

  /** Programmordner unter Windows (64-bit zuerst). */
  winPaths(dir, file) {
    const roots = [this.env.ProgramFiles, this.env.ProgramW6432, this.env['ProgramFiles(x86)'], 'C:\\Program Files'].filter(Boolean);
    return [...new Set(roots)].map((r) => path.win32.join(r, dir, file));
  }

  /** { installed, wireguard, wg, wgQuick, supported } */
  async detect() {
    if (this.win) {
      const wireguard = this.winPaths('WireGuard', 'wireguard.exe').find((p) => this.exists(p)) || null;
      const wg = wireguard ? path.win32.join(path.win32.dirname(wireguard), 'wg.exe') : null;
      return { supported: true, installed: !!wireguard, wireguard, wg: wg && this.exists(wg) ? wg : null };
    }
    if (this.platform === 'linux') {
      const wgQuick = await this.which('wg-quick');
      const wg = await this.which('wg');
      return { supported: true, installed: !!wgQuick, wgQuick, wg };
    }
    return { supported: false, installed: false };
  }

  /** Läuft der Tunnel? { running, service } – service: Windows-Dienst ist eingerichtet (auch gestoppt). */
  async tunnel(det) {
    if (this.win) {
      const r = await this.run('sc', ['query', `WireGuardTunnel$${IFACE}`]);
      const out = String(r.stdout || '');
      return { running: /STATE\s*:\s*4\s+RUNNING/i.test(out) || /\bRUNNING\b/.test(out), service: /SERVICE_NAME/i.test(out) };
    }
    if (this.platform === 'linux') return { running: this.exists(`/sys/class/net/${IFACE}`), service: false };
    return { running: false, service: false, det };
  }

  /** Letzter Handschlag je öffentlichem Schlüssel (wg show <iface> dump). Ohne Rechte → {} (kein Fehler). */
  async handshakes(det) {
    if (!det || !det.wg) return {};
    const r = await this.run(det.wg, ['show', IFACE, 'dump']);
    if (r.code !== 0 || !r.stdout) return {};
    const out = {};
    const lines = String(r.stdout).trim().split(/\r?\n/).slice(1); // erste Zeile = Schnittstelle
    for (const l of lines) {
      const [pub, , endpoint, , last, rx, tx] = l.split('\t');
      if (pub) out[pub] = { endpoint: endpoint && endpoint !== '(none)' ? endpoint : null, lastHandshake: Number(last) ? Number(last) * 1000 : null, rx: Number(rx) || 0, tx: Number(tx) || 0 };
    }
    return out;
  }

  /** Tunnel starten. Braucht Administrator-Rechte – der Aufrufer hat vorher ausdrücklich zugestimmt. */
  async start(det, confFile) {
    if (!det.installed) throw Object.assign(new Error('WireGuard is not installed.'), { status: 409 });
    const code = this.win ? await this.elevated(det.wireguard, ['/installtunnelservice', confFile]) : await this.elevated(det.wgQuick, ['up', confFile]);
    if (code !== 0) throw Object.assign(new Error(this.win ? 'WireGuard did not start – the administrator prompt was declined or the tunnel already exists (code {code}).' : 'wg-quick did not start – the password prompt was declined or failed (code {code}).'), { status: 409, vars: { code } });
  }

  async stop(det, confFile) {
    if (!det.installed) throw Object.assign(new Error('WireGuard is not installed.'), { status: 409 });
    const code = this.win ? await this.elevated(det.wireguard, ['/uninstalltunnelservice', IFACE]) : await this.elevated(det.wgQuick, ['down', confFile]);
    if (code !== 0) throw Object.assign(new Error('Stopping did not work – the administrator prompt was declined (code {code}).'), { status: 409, vars: { code } });
  }

  /** Befehl zum Selbst-Eintippen (wenn es keine grafische Abfrage gibt, z. B. Linux ohne Desktop). */
  manualCommand(action, confFile) {
    if (this.win) return action === 'start' ? `wireguard.exe /installtunnelservice "${confFile}"` : `wireguard.exe /uninstalltunnelservice ${IFACE}`;
    return `sudo wg-quick ${action === 'start' ? 'up' : 'down'} "${confFile}"`;
  }

  /** Tailscale: nur lesen. { installed, running, state, name, ips, peers, online, tailnet } */
  async tailscale() {
    const exe = this.win ? this.winPaths('Tailscale', 'tailscale.exe').find((p) => this.exists(p)) : await this.which('tailscale');
    if (!exe) return { installed: false };
    const r = await this.run(exe, ['status', '--json']);
    let j = null;
    try { j = JSON.parse(r.stdout); } catch { return { installed: true, running: false, state: 'Unknown' }; }
    const peers = Object.values(j.Peer || {});
    const self = j.Self || {};
    return {
      installed: true, running: j.BackendState === 'Running', state: j.BackendState || 'Unknown',
      name: self.HostName || null, dnsName: self.DNSName ? String(self.DNSName).replace(/\.$/, '') : null, ips: self.TailscaleIPs || [],
      tailnet: (j.CurrentTailnet && j.CurrentTailnet.Name) || null, peers: peers.length, online: peers.filter((p) => p.Online).length,
    };
  }
}

/** Anleitung zum Installieren (Text Englisch – Deutsch über locales/de.json). */
function installGuide(platform, pkgHint) {
  if (platform === 'win32') return { steps: ['Download WireGuard for Windows from wireguard.com/install and install it.', 'Come back here – Hostwerk finds it by itself.'], command: 'winget install WireGuard.WireGuard', url: 'https://www.wireguard.com/install/' };
  if (platform === 'linux') return { steps: ['Install the package wireguard-tools.', 'Come back here – Hostwerk finds it by itself.'], command: (pkgHint && pkgHint({ apt: 'wireguard-tools', dnf: 'wireguard-tools', pacman: 'wireguard-tools', zypper: 'wireguard-tools' })) || 'sudo apt install wireguard-tools', url: 'https://www.wireguard.com/install/' };
  return { steps: ['This system is not supported for the tunnel – use the WireGuard app and import a configuration by hand.'], command: '', url: 'https://www.wireguard.com/install/' };
}

module.exports = { WgSystem, installGuide };
