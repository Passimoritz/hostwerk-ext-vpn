'use strict';
/*
 * WireGuard und andere VPNs auf diesem Rechner: installiert? läuft der Tunnel? starten/stoppen, Zugänge im laufenden
 * Tunnel nachziehen, Version – plus Tailscale/Headscale, ZeroTier und NetBird nur lesend.
 *
 * Alles, was das System berührt, kommt von außen herein (run, elevated, batch, exists) – die Tests bilden es nach, beim
 * Entwickeln wird nichts gestartet und keine Netzwerk-Einstellung angefasst.
 *   run(cmd, args)       → Promise<{ code, stdout }>   normales Programm (lesend; „wg set“ nur, wenn die Rechte reichen)
 *   elevated(cmd, args)  → Promise<exitCode>           mit Administrator-Rechten (Windows: UAC, Linux: pkexec)
 *   batch(steps)         → Promise<{ code, steps }>    mehrere Befehle mit EINER Administrator-Abfrage (Hostwerk 2.12+, sonst null)
 *   exists(path)         → boolean
 *
 * Windows: Tunnel als Dienst "WireGuardTunnel$hostwerk" (wireguard.exe /installtunnelservice <datei>), Linux: wg-quick.
 * Tailscale, ZeroTier und NetBird werden nur gelesen – Hostwerk legt dort keine Konten an und ändert nichts.
 */
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { IFACE } = require('./wgconf');

class WgSystem {
  constructor({ platform = process.platform, env = process.env, run, elevated, batch = null, exists, which }) {
    this.platform = platform; this.env = env; this.run = run; this.elevated = elevated; this.batch = batch; this.exists = exists; this.which = which || (async () => null);
  }
  get win() { return this.platform === 'win32'; }

  /** Programmordner unter Windows (64-bit zuerst). */
  winPaths(dir, file) {
    const roots = [this.env.ProgramFiles, this.env.ProgramW6432, this.env['ProgramFiles(x86)'], 'C:\\Program Files', 'C:\\Program Files (x86)'].filter(Boolean);
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

  /**
   * Installierte Version: Windows aus der Programmdatei (Dateiversion, nur lesen), Linux aus „wg --version“.
   * → '0.5.3' | '1.0.20210914' | null
   */
  async version(det) {
    if (!det || !det.installed) return null;
    if (this.win) {
      const q = `(Get-Item -LiteralPath '${String(det.wireguard).replace(/'/g, "''")}').VersionInfo.ProductVersion`;
      const r = await this.run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', q]);
      const m = /(\d+\.\d+(?:\.\d+)*)/.exec(r.stdout || '');
      return r.code === 0 && m ? m[1] : null;
    }
    if (!det.wg) return null;
    const r = await this.run(det.wg, ['--version']);
    const m = /v(\d+\.\d+(?:\.\d+)*)/.exec(r.stdout || '');
    return m ? m[1] : null;
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
      const [pub, , endpoint, allowed, last, rx, tx] = l.split('\t');
      if (pub) out[pub] = { endpoint: endpoint && endpoint !== '(none)' ? endpoint : null, allowed: allowed || '', lastHandshake: Number(last) ? Number(last) * 1000 : null, rx: Number(rx) || 0, tx: Number(tx) || 0 };
    }
    return out;
  }

  /**
   * Zugänge im LAUFENDEN Tunnel nachziehen, ohne Neustart: „wg set“ entfernt bzw. fügt Peers hinzu. Klappt nur, wenn
   * Hostwerk die Rechte dafür hat (z. B. als Systemdienst) – sonst false, und es bleibt beim Hinweis „Neustart nötig“.
   *   add: [{ publicKey, presharedKey, address }]  remove: [publicKey]   → true = alles übernommen
   */
  async applyLive(det, { add = [], remove = [] } = {}) {
    if (!det || !det.wg) return false;
    for (const pub of remove) { const r = await this.run(det.wg, ['set', IFACE, 'peer', pub, 'remove']); if (r.code !== 0) return false; }
    for (const p of add) {
      // PresharedKey nur über eine Datei (nicht in der Befehlszeile sichtbar) – nur für den Besitzer lesbar, gleich wieder weg
      const f = path.join(os.tmpdir(), `hw-vpn-${crypto.randomBytes(6).toString('hex')}.key`);
      try {
        if (p.presharedKey) fs.writeFileSync(f, `${p.presharedKey}\n`, { mode: 0o600 });
        const r = await this.run(det.wg, ['set', IFACE, 'peer', p.publicKey, ...(p.presharedKey ? ['preshared-key', f] : []), 'allowed-ips', `${p.address}/32`]);
        if (r.code !== 0) return false;
      } finally { try { fs.rmSync(f, { force: true }); } catch { /* weg */ } }
    }
    return true;
  }

  /**
   * Tunnel starten. Braucht Administrator-Rechte – der Aufrufer hat vorher ausdrücklich zugestimmt. extra = weitere
   * Befehle unter derselben Abfrage (Windows-Firewall für „nur bestimmte Dienste“, siehe wgconf.winFirewall).
   */
  async start(det, confFile, extra = []) {
    if (!det.installed) throw Object.assign(new Error('WireGuard is not installed.'), { status: 409 });
    const main = this.win ? { cmd: det.wireguard, args: ['/installtunnelservice', confFile] } : { cmd: det.wgQuick, args: ['up', confFile] };
    let code;
    if (extra.length) {
      if (!this.batch) throw Object.assign(new Error('Limiting an access to single services needs Hostwerk 2.12 or newer.'), { status: 409 });
      code = (await this.batch([main, ...extra])).code;
    } else code = await this.elevated(main.cmd, main.args);
    if (code !== 0) throw Object.assign(new Error(this.win ? 'WireGuard did not start – the administrator prompt was declined or the tunnel already exists (code {code}).' : 'wg-quick did not start – the password prompt was declined or failed (code {code}).'), { status: 409, vars: { code } });
  }

  async stop(det, confFile, extra = []) {
    if (!det.installed) throw Object.assign(new Error('WireGuard is not installed.'), { status: 409 });
    const main = this.win ? { cmd: det.wireguard, args: ['/uninstalltunnelservice', IFACE] } : { cmd: det.wgQuick, args: ['down', confFile] };
    // Firewall-Regeln wegräumen gehört dazu – ein Fehler dort (Regel schon weg) hält das Stoppen nicht auf
    let code;
    if (extra.length && this.batch) { const r = await this.batch([main, ...extra], { keepGoing: true }); code = r.steps.length ? r.steps[0].code : r.code; } else code = await this.elevated(main.cmd, main.args);
    if (code !== 0) throw Object.assign(new Error('Stopping did not work – the administrator prompt was declined (code {code}).'), { status: 409, vars: { code } });
  }

  /** Befehl zum Selbst-Eintippen (wenn es keine grafische Abfrage gibt, z. B. Linux ohne Desktop). */
  manualCommand(action, confFile) {
    if (this.win) return action === 'start' ? `wireguard.exe /installtunnelservice "${confFile}"` : `wireguard.exe /uninstalltunnelservice ${IFACE}`;
    return `sudo wg-quick ${action === 'start' ? 'up' : 'down'} "${confFile}"`;
  }

  /** JSON eines lesenden Befehls oder { error: true }. */
  async json(cmd, args) {
    const r = await this.run(cmd, args);
    if (r.code !== 0 && !r.stdout) return { error: true };
    try { return JSON.parse(r.stdout); } catch { return { error: true }; }
  }

  /**
   * Tailscale: nur lesen. { installed, running, state, name, dnsName, ips, tailnet, peers, online, devices, exitNode,
   * advertises: { exitNode, routes }, controlUrl, headscale }
   */
  async tailscale() {
    const exe = this.win ? this.winPaths('Tailscale', 'tailscale.exe').find((p) => this.exists(p)) : await this.which('tailscale');
    if (!exe) return { installed: false };
    const j = await this.json(exe, ['status', '--json']);
    if (j.error) return { installed: true, running: false, state: 'Unknown' };
    const peers = Object.values(j.Peer || {});
    const self = j.Self || {};
    // Einstellungen dieses Geräts (Exit-Node/Subnetz anbieten, eigener Steuer-Server = Headscale) – fehlt bei alten Versionen
    const prefs = await this.json(exe, ['debug', 'prefs']).catch(() => ({ error: true }));
    const adv = Array.isArray(prefs.AdvertiseRoutes) ? prefs.AdvertiseRoutes : [];
    const controlUrl = !prefs.error && prefs.ControlURL ? String(prefs.ControlURL) : null;
    const devices = peers.map((p) => ({
      name: p.HostName || (p.DNSName ? String(p.DNSName).split('.')[0] : '?'), os: p.OS || '', ips: p.TailscaleIPs || [], online: !!p.Online,
      exitNode: !!p.ExitNode, exitNodeOption: !!p.ExitNodeOption, lastSeen: p.LastSeen && !/^0001/.test(p.LastSeen) ? Date.parse(p.LastSeen) || null : null,
    })).sort((a, b) => (b.online - a.online) || a.name.localeCompare(b.name)).slice(0, 100);
    return {
      installed: true, running: j.BackendState === 'Running', state: j.BackendState || 'Unknown',
      name: self.HostName || null, dnsName: self.DNSName ? String(self.DNSName).replace(/\.$/, '') : null, ips: self.TailscaleIPs || [],
      tailnet: (j.CurrentTailnet && j.CurrentTailnet.Name) || null, peers: peers.length, online: peers.filter((p) => p.Online).length,
      devices, exitNode: (devices.find((d) => d.exitNode) || {}).name || null,
      advertises: { exitNode: adv.includes('0.0.0.0/0') || adv.includes('::/0'), routes: adv.filter((r) => r !== '0.0.0.0/0' && r !== '::/0') },
      controlUrl, headscale: !!(controlUrl && !/(^|\.)tailscale\.com(\/|$|:)/i.test(controlUrl.replace(/^https?:\/\//, ''))),
    };
  }

  /** Headscale (eigener Tailscale-Steuer-Server) auf diesem Rechner? Nur ob das Programm da ist – Konfiguration bleibt beim Nutzer. */
  async headscale() {
    const exe = this.win ? null : await this.which('headscale');
    if (!exe) return { installed: false };
    const r = await this.run(exe, ['version']);
    const m = /v?(\d+\.\d+(?:\.\d+)*)/.exec(r.stdout || '');
    return { installed: true, version: m ? m[1] : null };
  }

  /** ZeroTier: nur lesen. Die Abfrage braucht oft Administrator-Rechte (Schlüsseldatei) – dann { installed, needsAdmin }. */
  async zerotier() {
    const exe = this.win
      ? [path.win32.join(this.env.ProgramData || 'C:\\ProgramData', 'ZeroTier', 'One', 'zerotier-one_x64.exe'), path.win32.join(this.env.ProgramData || 'C:\\ProgramData', 'ZeroTier', 'One', 'zerotier-one_x86.exe')].find((p) => this.exists(p))
      : await this.which('zerotier-cli');
    if (!exe) return { installed: false };
    const pre = this.win ? ['-q'] : [];
    const info = await this.json(exe, [...pre, '-j', 'info']);
    if (info.error || !info.address) return { installed: true, needsAdmin: true };
    const nets = await this.json(exe, [...pre, '-j', 'listnetworks']);
    return {
      installed: true, online: !!info.online, address: info.address, version: info.version || null,
      networks: Array.isArray(nets) ? nets.slice(0, 20).map((n) => ({ id: n.nwid || n.id, name: n.name || '', status: n.status || '', ips: n.assignedAddresses || [] })) : [],
    };
  }

  /** NetBird: nur lesen („netbird status --json“). */
  async netbird() {
    const exe = this.win ? this.winPaths('Netbird', 'netbird.exe').find((p) => this.exists(p)) : await this.which('netbird');
    if (!exe) return { installed: false };
    const j = await this.json(exe, ['status', '--json']);
    if (j.error) return { installed: true, running: false };
    const p = j.peers || {};
    return {
      installed: true, running: !!(j.management && j.management.connected), ip: j.netbirdIp || null, fqdn: j.fqdn || null,
      management: (j.management && j.management.url) || null, peers: Number(p.total) || 0, online: Number(p.connected) || 0, version: j.daemonVersion || j.cliVersion || null,
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
