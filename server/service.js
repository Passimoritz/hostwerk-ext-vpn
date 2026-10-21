'use strict';
/*
 * VPN-Zugang: Einstellungen, Zugänge je Person/Gerät, Konfigurationen und QR-Codes, Tunnel starten/stoppen.
 *
 * Daten: data/vpn/state.json – private Schlüssel und PresharedKeys mit core/secrets versiegelt. Die Datei für WireGuard
 * (data/vpn/hostwerk.conf, nur für den Besitzer lesbar) entsteht erst beim Starten und wird beim Stoppen gelöscht.
 * Ändern sich Zugänge, während der Tunnel läuft, merkt sich der Dienst „Neustart nötig“ – Hostwerk startet nichts
 * selbst mit Administrator-Rechten.
 *
 * Dienst (ctx.vpn): status(), peers(), addPeer({ person, device, member }), removePeer(id), config(id)
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const K = require('./keys');
const W = require('./wgconf');
const { installGuide } = require('./system');

const bad = (status, text, vars) => Object.assign(new Error(text), { status, vars });

class VpnService {
  /**
   * dir      Datenordner (data/vpn)
   * secrets  { seal, open }
   * system   WgSystem (oder Nachbildung)
   * qr       (text) → Promise<svg>  (Hostwerks qrcode-Bibliothek)
   * ctx      Hostwerk-Kontext (router, users), optional
   */
  constructor({ dir, secrets, system, qr, ctx = {}, platform = process.platform, pkgHint = null, broadcast = () => {} }) {
    this.dir = dir; this.secrets = secrets; this.sys = system; this.qr = qr; this.ctx = ctx; this.platform = platform; this.pkgHint = pkgHint; this.broadcast = broadcast;
    fs.mkdirSync(dir, { recursive: true });
  }

  /* ---------------- Speicher ---------------- */
  file() { return path.join(this.dir, 'state.json'); }
  confFile() { return path.join(this.dir, `${W.IFACE}.conf`); }
  load() {
    let s = null;
    try { s = JSON.parse(fs.readFileSync(this.file(), 'utf8')); } catch { s = null; }
    if (!s || !s.server) {
      const kp = K.keyPair();
      s = { settings: { ...W.DEFAULTS }, server: { publicKey: kp.publicKey, privateKey: this.secrets.seal(kp.privateKey) }, peers: [], needsRestart: false };
      this.save(s);
    }
    s.settings = { ...W.DEFAULTS, ...(s.settings || {}) };
    s.peers = s.peers || [];
    return s;
  }
  save(s) { const f = this.file(); fs.writeFileSync(`${f}.tmp`, JSON.stringify(s, null, 1), { mode: 0o600 }); fs.renameSync(`${f}.tmp`, f); }

  pubPeer(p, hs = {}) {
    const h = hs[p.publicKey] || null;
    return { id: p.id, person: p.person, device: p.device || '', member: p.member || null, address: p.address, publicKey: p.publicKey, enabled: p.enabled !== false, created: p.created, lastHandshake: h ? h.lastHandshake : null, endpoint: h ? h.endpoint : null, rx: h ? h.rx : null, tx: h ? h.tx : null };
  }

  /* ---------------- Zustand ---------------- */
  async status() {
    const s = this.load();
    const det = await this.sys.detect();
    const tun = det.installed ? await this.sys.tunnel(det) : { running: false, service: false };
    const hs = tun.running ? await this.sys.handshakes(det).catch(() => ({})) : {};
    let tailscale = { installed: false };
    try { tailscale = await this.sys.tailscale(); } catch { /* nur Anzeige */ }
    return {
      platform: this.platform,
      wireguard: { supported: det.supported, installed: det.installed, running: tun.running, service: tun.service, guide: det.installed ? null : installGuide(this.platform, this.pkgHint) },
      settings: s.settings, serverPublicKey: s.server.publicKey, serverAddress: W.serverAddress(s.settings.subnet),
      needsRestart: !!(s.needsRestart && tun.running),
      peers: s.peers.map((p) => this.pubPeer(p, hs)),
      tailscale,
      router: !!(this.ctx.router && typeof this.ctx.router.forward === 'function'),
      team: !!(this.ctx.users && Array.isArray(this.ctx.users.list)),
      lanOk: this.platform === 'linux',
    };
  }

  /** Mitglieder aus „Team & Rollen“ (nur Name und Kennung). */
  members() {
    const u = this.ctx.users;
    if (!u || !Array.isArray(u.list)) return [];
    return u.list.filter((m) => m.enabled !== false).map((m) => ({ id: m.id, name: m.name }));
  }

  async saveSettings(b) {
    const s = this.load();
    s.settings = W.settings({ ...s.settings, ...(b || {}) }, this.platform);
    s.needsRestart = true;
    this.save(s);
    return this.status();
  }

  /** Vorschlag für die Adresse von außen: DynDNS-Name oder öffentliche IPv4 der Router-Erweiterung. */
  async suggestEndpoint() {
    const r = this.ctx.router;
    if (!r) return { endpoint: null };
    try {
      const dyn = r.dyn && r.dyn.domain ? String(r.dyn.domain) : '';
      if (dyn) return { endpoint: dyn, source: 'dyndns' };
      const n = typeof r.net === 'function' ? await r.net() : null;
      return n && n.v4public ? { endpoint: n.v4public, source: 'ip' } : { endpoint: null };
    } catch { return { endpoint: null }; }
  }

  /* ---------------- Zugänge ---------------- */
  addPeer(b = {}) {
    const s = this.load();
    const person = String(b.person || '').trim().slice(0, 40);
    const device = String(b.device || '').trim().slice(0, 40);
    if (!person) throw bad(400, 'Who is the access for? Enter a name.');
    const member = b.member ? this.members().find((m) => m.id === b.member) : null;
    if (b.member && !member) throw bad(404, 'Team member not found');
    if (s.peers.some((p) => p.person.toLowerCase() === person.toLowerCase() && (p.device || '').toLowerCase() === device.toLowerCase())) throw bad(409, 'This person already has an access for this device – give the device a name.');
    const kp = K.keyPair();
    const peer = {
      id: crypto.randomBytes(5).toString('hex'), person, device, member: member ? member.id : null,
      address: W.nextAddress(s.settings.subnet, s.peers.map((p) => p.address)),
      publicKey: kp.publicKey, privateKey: this.secrets.seal(kp.privateKey), presharedKey: this.secrets.seal(K.presharedKey()), enabled: true, created: Date.now(),
    };
    s.peers.push(peer); s.needsRestart = true;
    this.save(s);
    return this.pubPeer(peer);
  }
  peer(s, id) { const p = s.peers.find((x) => x.id === id); if (!p) throw bad(404, 'Access not found'); return p; }
  updatePeer(id, b = {}) {
    const s = this.load(); const p = this.peer(s, id);
    if (b.person !== undefined) { const n = String(b.person).trim().slice(0, 40); if (!n) throw bad(400, 'Who is the access for? Enter a name.'); p.person = n; }
    if (b.device !== undefined) p.device = String(b.device).trim().slice(0, 40);
    if (b.enabled !== undefined) p.enabled = !!b.enabled;
    s.needsRestart = true; this.save(s);
    return this.pubPeer(p);
  }
  /** Neue Schlüssel (z. B. Handy verloren) – die alte Konfiguration geht danach nicht mehr. */
  rekeyPeer(id) {
    const s = this.load(); const p = this.peer(s, id);
    const kp = K.keyPair();
    Object.assign(p, { publicKey: kp.publicKey, privateKey: this.secrets.seal(kp.privateKey), presharedKey: this.secrets.seal(K.presharedKey()) });
    s.needsRestart = true; this.save(s);
    return this.pubPeer(p);
  }
  removePeer(id) { const s = this.load(); this.peer(s, id); s.peers = s.peers.filter((p) => p.id !== id); s.needsRestart = true; this.save(s); }
  peers() { return this.load().peers.map((p) => this.pubPeer(p)); }

  /** Konfiguration eines Geräts (Klartext mit privatem Schlüssel – nur für den Besitzer dieses PCs) + QR-Code als SVG. */
  async config(id) {
    const s = this.load(); const p = this.peer(s, id);
    const text = W.clientConfig({ settings: s.settings, serverPublicKey: s.server.publicKey, peer: p, privateKey: this.secrets.open(p.privateKey), presharedKey: this.secrets.open(p.presharedKey) });
    const svg = this.qr ? await this.qr(text) : null;
    return { file: W.fileName(p), text, qr: svg };
  }

  /* ---------------- Tunnel ---------------- */
  serverConfigText(s) {
    return W.serverConfig({
      settings: s.settings, privateKey: this.secrets.open(s.server.privateKey), platform: this.platform,
      peers: s.peers.map((p) => ({ ...p, presharedKey: this.secrets.open(p.presharedKey) })),
    });
  }

  /** Starten – nur mit confirm: true (die Oberfläche hat vorher gefragt und auf die Administrator-Abfrage hingewiesen). */
  async start({ confirm } = {}) {
    if (confirm !== true) throw bad(428, 'Starting needs your confirmation – WireGuard asks for administrator rights.');
    const s = this.load();
    const det = await this.sys.detect();
    if (!det.installed) throw bad(409, 'WireGuard is not installed.');
    if (!s.peers.some((p) => p.enabled !== false)) throw bad(409, 'Add an access first.');
    const tun = await this.sys.tunnel(det);
    if (tun.running || tun.service) throw bad(409, 'The tunnel is running already – stop it first.');
    fs.writeFileSync(this.confFile(), this.serverConfigText(s), { mode: 0o600 });
    try { await this.sys.start(det, this.confFile()); } catch (e) {
      fs.rmSync(this.confFile(), { force: true });
      throw Object.assign(e, { manual: this.sys.manualCommand('start', this.confFile()) });
    }
    s.needsRestart = false; this.save(s);
    this.broadcast({ type: 'vpn' });
    return this.status();
  }

  async stop({ confirm } = {}) {
    if (confirm !== true) throw bad(428, 'Stopping needs your confirmation – WireGuard asks for administrator rights.');
    const det = await this.sys.detect();
    try { await this.sys.stop(det, this.confFile()); } catch (e) { throw Object.assign(e, { manual: this.sys.manualCommand('stop', this.confFile()) }); }
    // Windows liest die Datei nur beim Einrichten des Dienstes, Linux beim Abbauen – danach weg mit dem Schlüssel
    fs.rmSync(this.confFile(), { force: true });
    this.broadcast({ type: 'vpn' });
    return this.status();
  }

  /** UDP-Port über die Erweiterung „Router & Portfreigaben“ freigeben (und dort merken, damit er bleibt). */
  async forward() {
    const r = this.ctx.router;
    if (!r || typeof r.forward !== 'function') throw bad(409, 'The extension “Router & port forwarding” is not installed.');
    const { port } = this.load().settings;
    const res = await r.forward({ port, protocol: 'UDP', label: 'WireGuard (VPN)' });
    if (r.cfg && Array.isArray(r.cfg.extra)) {
      r.cfg.extra = [...r.cfg.extra.filter((e) => !(e.port === port && e.protocol === 'UDP')), { port, protocol: 'UDP', label: 'WireGuard (VPN)' }];
      if (this.ctx.settings && typeof this.ctx.settings.save === 'function') this.ctx.settings.save();
    }
    return { ...res, port };
  }
}

module.exports = { VpnService };
