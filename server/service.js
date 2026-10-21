'use strict';
/*
 * VPN-Zugang: Einstellungen, Zugänge je Person/Gerät, Konfigurationen und QR-Codes, Tunnel starten/stoppen – und die
 * Wartung, die ohne Zutun läuft (tick(), alle 15 Minuten):
 *   - abgelaufene Zugänge sperren und, wenn die Rechte reichen, gleich aus dem laufenden Tunnel nehmen („wg set“)
 *   - „zuletzt verbunden“ und Datenmenge je Zugang merken (auch wenn der Tunnel später aus ist)
 *   - Adresse von außen: eigener Name über die DNS-Erweiterung auf die öffentliche IP halten (A/AAAA), DynDNS-Name der
 *     Router-Erweiterung übernehmen, bei fester IP einen IP-Wechsel melden
 *   - UDP-Port über die Router-Erweiterung freigeben (router.forwards mit Besitzer „vpn“) und nachziehen
 *   - Verbindungsart (Carrier-NAT, DS-Lite) erkennen, WireGuard-Updates prüfen (Windows: offizielle Liste)
 *   - Befunde gebündelt: EINE Benachrichtigung mit allem Neuen, Wächter-Eintrag, Selbstwartung
 *
 * Daten: data/vpn/state.json – private Schlüssel und PresharedKeys mit core/secrets versiegelt. Die Datei für WireGuard
 * (data/vpn/hostwerk.conf, nur für den Besitzer lesbar) entsteht erst beim Starten und wird beim Stoppen gelöscht.
 * Lässt sich eine Änderung nicht im laufenden Tunnel übernehmen, merkt sich der Dienst „Neustart nötig“ – Hostwerk startet
 * nichts selbst mit Administrator-Rechten.
 *
 * Dienst (ctx.vpn): status(), peers(), addPeer({ person, device, member, platform, reach, services, expires }), removePeer(id), config(id)
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const K = require('./keys');
const W = require('./wgconf');
const M = require('./maint');
const { installGuide } = require('./system');

const bad = (status, text, vars) => Object.assign(new Error(text), { status, vars });
const OWNER = 'vpn';
const LABEL = 'WireGuard (VPN)';

class VpnService {
  /**
   * dir      Datenordner (data/vpn)
   * secrets  { seal, open }
   * system   WgSystem (oder Nachbildung)
   * qr       (text) → Promise<svg>  (Hostwerks qrcode-Bibliothek)
   * ctx      Hostwerk-Kontext (router, users, dns, keeper), optional
   * t        Übersetzer (host.t) für Meldungen aus der Wartung
   * notify   ({ title, text, kind }) → Benachrichtigung (host.notifications), optional
   * watcher  ({ id, label, state, detail }) → Wächter-Liste, optional
   * fetch    für die Update-Prüfung (Tests: Nachbildung)
   */
  constructor({ dir, secrets, system, qr, ctx = {}, platform = process.platform, pkgHint = null, broadcast = () => {}, t = (s, v) => (v ? String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] !== undefined ? v[k] : m)) : s), notify = null, watcher = null, fetch: fetchFn = (typeof fetch === 'function' ? fetch : null), timers = false }) {
    this.dir = dir; this.secrets = secrets; this.sys = system; this.qr = qr; this.ctx = ctx; this.platform = platform; this.pkgHint = pkgHint; this.broadcast = broadcast;
    this.t = t; this.notify = notify; this.watcher = watcher; this.fetch = fetchFn;
    fs.mkdirSync(dir, { recursive: true });
    if (timers) {
      this.timer = setTimeout(() => this.tick().catch(() => {}), 30000);
      this.interval = setInterval(() => this.tick().catch(() => {}), 15 * 60000);
      for (const x of [this.timer, this.interval]) if (x.unref) x.unref();
    }
  }
  /** Zeitgeber beenden (Erweiterung entfernt/aktualisiert) – nicht verwechseln mit stop() = Tunnel stoppen */
  dispose() { clearTimeout(this.timer); clearInterval(this.interval); clearTimeout(this.liveTimer); }

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
    s.health = s.health || { at: 0, issues: [], seen: [] };
    return s;
  }
  save(s) { const f = this.file(); fs.writeFileSync(`${f}.tmp`, JSON.stringify(s, null, 1), { mode: 0o600 }); fs.renameSync(`${f}.tmp`, f); }

  pubPeer(p, hs = {}, months = 0) {
    const h = hs[p.publicKey] || null;
    return {
      id: p.id, person: p.person, device: p.device || '', member: p.member || null, address: p.address, publicKey: p.publicKey, enabled: p.enabled !== false, created: p.created,
      platform: p.platform || 'other', reach: W.reachOf(p), services: p.services || [], expires: p.expires || null, lock: p.lock || null, keyAt: p.keyAt || p.created,
      rotationDue: M.rotationDue([p], months).length > 0,
      // Live (Tunnel läuft, Rechte reichen) – sonst das zuletzt Gemerkte
      lastHandshake: h && h.lastHandshake ? h.lastHandshake : (p.lastSeen || null), endpoint: h ? h.endpoint : null,
      rx: h ? h.rx : (p.rx === undefined ? null : p.rx), tx: h ? h.tx : (p.tx === undefined ? null : p.tx), live: !!h,
    };
  }

  /* ---------------- Zustand ---------------- */
  async status() {
    const s = this.load();
    const det = await this.sys.detect();
    const tun = det.installed ? await this.sys.tunnel(det) : { running: false, service: false };
    const hs = tun.running ? await this.sys.handshakes(det).catch(() => ({})) : {};
    const r = this.ctx.router;
    return {
      platform: this.platform,
      wireguard: { supported: det.supported, installed: det.installed, running: tun.running, service: tun.service, guide: det.installed ? null : installGuide(this.platform, this.pkgHint), version: (s.update && s.update.installed) || null, latest: (s.update && s.update.latest) || null, live: Object.keys(hs).length > 0 },
      settings: s.settings, serverPublicKey: s.server.publicKey, serverAddress: W.serverAddress(s.settings.subnet),
      needsRestart: !!(s.needsRestart && tun.running), startedAt: s.startedAt || null, wantRunning: !!s.wantRunning,
      peers: s.peers.map((p) => this.pubPeer(p, hs, s.settings.rotateMonths)),
      router: !!(r && (typeof r.forward === 'function' || r.forwards)),
      dyndns: r && r.dyn && r.dyn.domain ? String(r.dyn.domain) : null,
      dnsExt: !!(this.ctx.dns && typeof this.ctx.dns.set === 'function'),
      team: !!(this.ctx.users && Array.isArray(this.ctx.users.list)),
      lanOk: this.platform === 'linux', fullOk: W.canFull(this.platform), servicesOk: this.platform === 'linux' || this.platform === 'win32',
      forward: s.forward || null, net: s.net || null, dnsState: s.dnsState || null,
      health: { at: s.health.at || null, issues: s.health.issues || [] },
    };
  }

  /** Andere VPNs auf diesem Rechner (nur lesen) – eigene Abfrage, weil sie mehrere Programme fragt. */
  async others() {
    const safe = async (fn) => { try { return await fn(); } catch { return { installed: false }; } };
    const [tailscale, headscale, zerotier, netbird] = await Promise.all([safe(() => this.sys.tailscale()), safe(() => this.sys.headscale()), safe(() => this.sys.zerotier()), safe(() => this.sys.netbird())]);
    return { platform: this.platform, tailscale, headscale, zerotier, netbird };
  }

  /** Mitglieder aus „Team & Rollen“ (nur Name und Kennung). */
  members() {
    const u = this.ctx.users;
    if (!u || !Array.isArray(u.list)) return [];
    return u.list.filter((m) => m.enabled !== false).map((m) => ({ id: m.id, name: m.name }));
  }

  async saveSettings(b) {
    const s = this.load();
    const before = s.settings;
    s.settings = W.settings({ ...s.settings, ...(b || {}) }, this.platform);
    // Adresse aus der Router-Erweiterung: ihr DynDNS-Name ist die Adresse
    if (s.settings.endpointMode === 'dyndns') { const d = this.ctx.router && this.ctx.router.dyn && this.ctx.router.dyn.domain; if (!d) throw bad(409, 'There is no DynDNS name in “Router & port forwarding” yet.'); s.settings.endpoint = W.checkEndpoint(d); }
    if (s.settings.endpointMode === 'dns' && !(this.ctx.dns && typeof this.ctx.dns.set === 'function')) throw bad(409, 'Keeping your own name up to date needs the extension “DNS management”.');
    const tunnelRelevant = ['port', 'subnet', 'scope', 'lanSubnet'].some((k) => before[k] !== s.settings[k]);
    if (tunnelRelevant) s.needsRestart = true;
    if (s.settings.endpoint !== before.endpoint) { s.endpointCheck = null; s.dnsState = null; }
    this.save(s);
    // Port geändert → Freigabe nachziehen; neuer eigener Name → gleich eintragen
    if (s.wantRunning && s.settings.autoForward && (before.port !== s.settings.port || !before.autoForward)) await this.ensureForward().catch(() => {});
    if (s.settings.endpointMode === 'dns') await this.ensureDns(true).catch(() => {});
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
    const opt = W.peerOptions(b, this.platform);
    const kp = K.keyPair();
    const now = Date.now();
    const peer = {
      id: crypto.randomBytes(5).toString('hex'), person, device, member: member ? member.id : null,
      address: W.nextAddress(s.settings.subnet, s.peers.map((p) => p.address)),
      publicKey: kp.publicKey, privateKey: this.secrets.seal(kp.privateKey), presharedKey: this.secrets.seal(K.presharedKey()), enabled: true, created: now, keyAt: now, ...opt,
    };
    s.peers.push(peer); s.needsRestart = true;
    this.save(s);
    this.queueLive();
    return this.pubPeer(peer);
  }
  peer(s, id) { const p = s.peers.find((x) => x.id === id); if (!p) throw bad(404, 'Access not found'); return p; }
  updatePeer(id, b = {}) {
    const s = this.load(); const p = this.peer(s, id);
    if (b.person !== undefined) { const n = String(b.person).trim().slice(0, 40); if (!n) throw bad(400, 'Who is the access for? Enter a name.'); p.person = n; }
    if (b.device !== undefined) p.device = String(b.device).trim().slice(0, 40);
    if (b.enabled !== undefined) p.enabled = !!b.enabled;
    if (['reach', 'services', 'platform', 'expires'].some((k) => b[k] !== undefined)) {
      Object.assign(p, W.peerOptions(b, this.platform, p));
      // Neues Ablaufdatum in der Zukunft hebt die Sperre „abgelaufen“ auf
      if (p.lock && p.lock.reason === 'expired' && (!p.expires || p.expires > Date.now())) delete p.lock;
    }
    if (b.locked !== undefined) {
      if (b.locked) p.lock = { reason: 'manual', at: Date.now() };
      else { delete p.lock; if (p.expires && p.expires <= Date.now()) p.expires = null; }
    }
    s.needsRestart = true; this.save(s);
    this.queueLive();
    return this.pubPeer(p);
  }
  /** Neue Schlüssel (z. B. Handy verloren) – die alte Konfiguration geht danach nicht mehr. */
  rekeyPeer(id) {
    const s = this.load(); const p = this.peer(s, id);
    const kp = K.keyPair();
    Object.assign(p, { publicKey: kp.publicKey, privateKey: this.secrets.seal(kp.privateKey), presharedKey: this.secrets.seal(K.presharedKey()), keyAt: Date.now() });
    s.needsRestart = true; this.save(s);
    this.queueLive();
    return this.pubPeer(p);
  }
  removePeer(id) { const s = this.load(); this.peer(s, id); s.peers = s.peers.filter((p) => p.id !== id); s.needsRestart = true; this.save(s); this.queueLive(); }
  peers() { const s = this.load(); return s.peers.map((p) => this.pubPeer(p, {}, s.settings.rotateMonths)); }

  /** Konfiguration eines Geräts (Klartext mit privatem Schlüssel – nur für den Besitzer dieses PCs) + QR-Code als SVG. */
  async config(id) {
    const s = this.load(); const p = this.peer(s, id);
    const text = W.clientConfig({ settings: s.settings, serverPublicKey: s.server.publicKey, peer: p, privateKey: this.secrets.open(p.privateKey), presharedKey: this.secrets.open(p.presharedKey) });
    const svg = this.qr ? await this.qr(text) : null;
    return { file: W.fileName(p), text, qr: svg, platform: p.platform || 'other' };
  }

  /* ---------------- Im laufenden Tunnel übernehmen ---------------- */
  /** Kennung der Firewall-Regeln – ändern sie sich, reicht „wg set“ nicht, dann ist ein Neustart nötig. */
  rulesKey(s) {
    const r = this.platform === 'linux' ? W.linuxRules(s.settings, s.peers) : W.winFirewall(s.peers);
    return crypto.createHash('sha256').update(JSON.stringify(r)).digest('hex').slice(0, 16);
  }
  /** Änderungen gesammelt kurz danach übernehmen (mehrere Klicks = ein Durchgang). */
  queueLive() {
    clearTimeout(this.liveTimer);
    this.liveTimer = setTimeout(() => this.syncLive().catch(() => {}), 300);
    if (this.liveTimer.unref) this.liveTimer.unref();
  }
  /**
   * Gewünschte Zugänge mit dem laufenden Tunnel abgleichen („wg set“ ohne Administrator-Abfrage). Klappt das (Rechte
   * reichen, Firewall-Regeln unverändert), entfällt „Neustart nötig“. → true | false
   */
  async syncLive() {
    const s = this.load();
    if (!s.needsRestart) return true;
    const det = await this.sys.detect();
    if (!det.installed) return false;
    const tun = await this.sys.tunnel(det);
    if (!tun.running) return false;
    if (s.appliedRules && s.appliedRules !== this.rulesKey(s)) return false;
    const live = await this.sys.handshakes(det).catch(() => ({}));
    const want = s.peers.filter(W.active);
    const remove = Object.keys(live).filter((pub) => !want.some((p) => p.publicKey === pub));
    const add = want.filter((p) => !live[p.publicKey] || live[p.publicKey].allowed !== `${p.address}/32`).map((p) => ({ publicKey: p.publicKey, address: p.address, presharedKey: this.secrets.open(p.presharedKey) }));
    const ok = await this.sys.applyLive(det, { add, remove });
    if (!ok) return false;
    const s2 = this.load(); s2.needsRestart = false; this.save(s2);
    this.broadcast({ type: 'vpn' });
    return true;
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
    if (!s.peers.some(W.active)) throw bad(409, 'Add an access first.');
    const tun = await this.sys.tunnel(det);
    if (tun.running || tun.service) throw bad(409, 'The tunnel is running already – stop it first.');
    fs.writeFileSync(this.confFile(), this.serverConfigText(s), { mode: 0o600 });
    const fw = this.platform === 'win32' ? W.winFirewall(s.peers, 'add') : [];
    try { await this.sys.start(det, this.confFile(), fw); } catch (e) {
      fs.rmSync(this.confFile(), { force: true });
      throw Object.assign(e, { manual: this.sys.manualCommand('start', this.confFile()) });
    }
    Object.assign(s, { needsRestart: false, wantRunning: true, startedAt: Date.now(), appliedRules: this.rulesKey(s), firewall: fw.map((c) => c.args[4]) });
    this.save(s);
    if (s.settings.autoForward) await this.ensureForward().catch(() => {});
    this.broadcast({ type: 'vpn' });
    return this.status();
  }

  async stop({ confirm } = {}) {
    if (confirm !== true) throw bad(428, 'Stopping needs your confirmation – WireGuard asks for administrator rights.');
    const det = await this.sys.detect();
    const s = this.load();
    // Firewall-Regeln genau so wegräumen, wie sie beim Start angelegt wurden (Namen gemerkt)
    const fw = (s.firewall || []).map((name) => ({ cmd: 'netsh', args: ['advfirewall', 'firewall', 'delete', 'rule', name] }));
    if (this.platform === 'linux' && !fs.existsSync(this.confFile())) fs.writeFileSync(this.confFile(), this.serverConfigText(s), { mode: 0o600 });
    try { await this.sys.stop(det, this.confFile(), fw); } catch (e) { throw Object.assign(e, { manual: this.sys.manualCommand('stop', this.confFile()) }); }
    fs.rmSync(this.confFile(), { force: true });
    const s2 = this.load();
    Object.assign(s2, { wantRunning: false, firewall: [], appliedRules: null });
    this.save(s2);
    if (s2.settings.autoForward) await this.dropForward().catch(() => {});
    this.broadcast({ type: 'vpn' });
    return this.status();
  }

  /* ---------------- Router: eine UDP-Freigabe ---------------- */
  /**
   * UDP-Port über „Router & Portfreigaben“ freigeben – mit Besitzer „vpn“ (router.forwards ab Router 1.2), damit die
   * Automatik ihn behält und die Router-Seite zeigt, woher er kommt. Ältere Router-Erweiterung: direkt + Merkliste.
   */
  async ensureForward() {
    const r = this.ctx.router;
    if (!r || (typeof r.forward !== 'function' && !r.forwards)) return this.noteForward({ state: 'none' });
    const { port } = this.load().settings;
    try {
      if (r.forwards && typeof r.forwards.add === 'function') {
        for (const o of r.forwards.owned(OWNER)) if (o.port !== port || o.protocol !== 'UDP') await r.forwards.remove(o, OWNER).catch(() => {});
        await r.forwards.add({ port, protocol: 'UDP', label: LABEL }, OWNER);
      } else {
        await r.forward({ port, protocol: 'UDP', label: LABEL });
        if (r.cfg && Array.isArray(r.cfg.extra)) {
          r.cfg.extra = [...r.cfg.extra.filter((e) => !(e.port === port && e.protocol === 'UDP')), { port, protocol: 'UDP', label: LABEL }];
          if (this.ctx.settings && typeof this.ctx.settings.save === 'function') this.ctx.settings.save();
        }
      }
      return this.noteForward({ state: 'ok', port });
    } catch (e) {
      this.noteForward({ state: 'failed', port, error: this.t(e.message) });
      throw e;
    }
  }
  /** Freigabe wieder entfernen (nur die eigene) – beim Stoppen, damit nichts offen steht, wo keiner zuhört. */
  async dropForward() {
    const r = this.ctx.router;
    if (!r || !r.forwards || typeof r.forwards.owned !== 'function') return;
    for (const o of r.forwards.owned(OWNER)) await r.forwards.remove(o, OWNER).catch(() => {});
    this.noteForward({ state: 'none' });
  }
  noteForward(f) { const s = this.load(); s.forward = { ...f, at: Date.now() }; this.save(s); return s.forward; }
  /** Knopf „Im Router freigeben“: wie die Automatik, Fehler sieht der Nutzer. */
  async forward() {
    const r = this.ctx.router;
    if (!r || (typeof r.forward !== 'function' && !r.forwards)) throw bad(409, 'The extension “Router & port forwarding” is not installed.');
    const f = await this.ensureForward();
    return { ...f, port: this.load().settings.port };
  }

  /* ---------------- Adresse von außen ---------------- */
  /** Öffentliche Adressen (Router-Erweiterung, sonst DNS-Erweiterung) → { v4, v6 } oder null */
  async publicAddress() {
    const r = this.ctx.router;
    try { if (r && typeof r.net === 'function') { const n = await r.net(); return { v4: n.v4public || null, v6: (n.v6 && n.v6.stable) || null }; } } catch { /* weiter */ }
    try { if (this.ctx.dns && typeof this.ctx.dns.publicAddress === 'function') { const a = await this.ctx.dns.publicAddress(); if (a && a.available && !a.error) return { v4: a.v4 || null, v6: a.v6 || null }; } } catch { /* nichts */ }
    return null;
  }
  /**
   * Eigener Name (Modus „dns“): A- und AAAA-Eintrag über die DNS-Erweiterung auf die öffentliche IP halten – nur, wenn
   * sich etwas geändert hat (oder einmal am Tag zur Sicherheit). → dnsState { v4, v6, ok, error, at }
   */
  async ensureDns(force = false) {
    const s = this.load();
    const dns = this.ctx.dns;
    if (s.settings.endpointMode !== 'dns' || !dns || typeof dns.set !== 'function') return null;
    const ip = await this.publicAddress();
    if (!ip || (!ip.v4 && !ip.v6)) return this.noteDns({ ok: false, error: this.t('The public address is unknown right now.') });
    const last = s.dnsState;
    if (!force && last && last.ok && last.v4 === ip.v4 && last.v6 === ip.v6 && Date.now() - last.at < M.DAY) return last;
    try {
      const name = s.settings.endpoint;
      if (ip.v4) await dns.set({ name, type: 'A', content: ip.v4, ttl: 300 });
      if (ip.v6) await dns.set({ name, type: 'AAAA', content: ip.v6, ttl: 300 });
      return this.noteDns({ ok: true, v4: ip.v4, v6: ip.v6 });
    } catch (e) { return this.noteDns({ ok: false, v4: ip.v4, v6: ip.v6, error: this.t(e.message) }); }
  }
  noteDns(d) { const s = this.load(); s.dnsState = { ...d, at: Date.now() }; this.save(s); return s.dnsState; }

  /* ---------------- Wartung ---------------- */
  /** Neueste WireGuard-Version (Windows: offizielle Liste) – höchstens einmal am Tag. */
  async checkUpdate(det, force = false) {
    const s = this.load();
    if (!s.settings.updateCheck || !det.installed) return s.update || null;
    if (!force && s.update && Date.now() - s.update.at < M.DAY) return s.update;
    const installed = await this.sys.version(det).catch(() => null);
    let latest = null;
    if (this.platform === 'win32' && this.fetch) {
      try { const r = await this.fetch(M.WIN_LATEST_URL, { headers: { 'user-agent': 'Hostwerk' }, signal: AbortSignal.timeout(15000) }); if (r.ok) latest = M.parseLatestWindows(await r.text()); } catch { /* offline – nächstes Mal */ }
    }
    // Linux: Updates kommen mit den Paketen des Systems – nur die installierte Version zeigen
    const s2 = this.load(); s2.update = { installed, latest, at: Date.now() }; this.save(s2);
    return s2.update;
  }

  /** Verbindungsart aus der Router-Erweiterung (Carrier-NAT, DS-Lite, IPv6) – höchstens stündlich. */
  async checkNet(force = false) {
    const s = this.load();
    const r = this.ctx.router;
    if (!r || typeof r.status !== 'function') return s.net || null;
    if (!force && s.net && Date.now() - s.net.at < 3600000) return s.net;
    try {
      const st = await r.status();
      const w = (st.wanted || []).find((x) => x.port === s.settings.port && x.protocol === 'UDP');
      const n = { cgnat: !!st.cgnat, dslite: !!st.dslite, v6: !!(st.net && st.net.v6 && st.net.v6.stable), publicIp: st.externalIp || (st.net && st.net.v4public) || null, mapped: w ? w.state : null, at: Date.now() };
      const s2 = this.load(); s2.net = n; this.save(s2);
      return n;
    } catch { return s.net || null; }
  }

  /**
   * Ein Wartungsdurchgang (alle 15 Minuten, auch per POST /vpn/check). Bündelt alles zu Befunden; Neues meldet EINE
   * Benachrichtigung. → { issues }
   */
  async tick({ force = false } = {}) {
    const now = Date.now();
    let s = this.load();
    // 1. Abgelaufene Zugänge sperren
    const expired = M.expiredPeers(s.peers, now);
    if (expired.length) {
      for (const p of expired) p.lock = { reason: 'expired', at: now };
      s.needsRestart = true; this.save(s);
    }
    // 2. Tunnel und Handschläge: „zuletzt verbunden“ und Datenmenge merken
    const det = await this.sys.detect();
    const tun = det.installed ? await this.sys.tunnel(det) : { running: false };
    if (tun.running) {
      const hs = await this.sys.handshakes(det).catch(() => ({}));
      if (Object.keys(hs).length) {
        s = this.load();
        for (const p of s.peers) { const h = hs[p.publicKey]; if (h) { if (h.lastHandshake) p.lastSeen = Math.max(p.lastSeen || 0, h.lastHandshake); p.rx = h.rx; p.tx = h.tx; } }
        this.save(s);
      }
      if (s.needsRestart) await this.syncLive().catch(() => false);
    }
    // 3. Adresse von außen
    s = this.load();
    if (s.settings.endpointMode === 'dyndns') {
      const d = this.ctx.router && this.ctx.router.dyn && this.ctx.router.dyn.domain;
      if (d && d !== s.settings.endpoint) { s.settings.endpoint = W.checkEndpoint(d); this.save(s); }
    }
    if (s.settings.endpointMode === 'dns') await this.ensureDns(force).catch(() => {});
    const netState = await this.checkNet(force);
    s = this.load();
    if (s.settings.endpoint && net.isIPv4(s.settings.endpoint) && netState && netState.publicIp && net.isIPv4(netState.publicIp)) {
      s.endpointCheck = { ipChanged: netState.publicIp !== s.settings.endpoint, publicIp: netState.publicIp, at: now };
      this.save(s);
    }
    // 4. Router-Freigabe nachziehen, wenn sie fehlt (Router neu gestartet, Freigabe gelöscht …)
    if (tun.running && s.settings.autoForward && this.ctx.router) {
      const missing = !s.forward || s.forward.state !== 'ok' || s.forward.port !== s.settings.port || (netState && netState.mapped === 'missing');
      if (missing) { await this.ensureForward().catch(() => {}); if (netState && netState.mapped === 'missing') await this.checkNet(true); }
    }
    // 5. Updates
    const update = await this.checkUpdate(det, force).catch(() => null);
    // 6. Befunde bündeln
    s = this.load();
    const issues = M.assess({
      installed: det.installed, running: tun.running, wantRunning: s.wantRunning, startedAt: s.startedAt, peers: s.peers, settings: s.settings,
      needsRestart: s.needsRestart, forward: s.forward, net: s.net, endpointCheck: s.endpointCheck, dns: s.dnsState, update, now,
    }).map((i) => ({ ...i, title: this.t(i.title), text: i.id === 'update' || i.id.startsWith('rotate-') || i.id === 'forward' || i.id === 'dns' ? i.text : this.t(i.text) }));
    const news = M.fresh(issues, s.health.seen);
    s.health = { at: now, issues, seen: issues.map((i) => i.id) };
    this.save(s);
    if (news.length && this.notify) {
      try { this.notify({ title: news.length === 1 ? news[0].title : this.t('VPN: {n} things need a look', { n: news.length }), text: news.map((i) => (news.length === 1 ? i.text : `• ${i.title}`)).join('\n'), kind: news.some((i) => i.level === 'err') ? 'error' : 'warn' }); } catch { /* Benachrichtigungen aus */ }
    }
    const bad2 = issues.filter((i) => i.level !== 'info');
    if (this.watcher) { try { this.watcher({ id: 'vpn', label: 'VPN (WireGuard)', state: !det.installed || (!tun.running && !s.wantRunning) ? 'off' : bad2.length ? 'alert' : 'ok', detail: bad2.length ? bad2.map((i) => i.title).join(' · ') : tun.running ? this.t('{n} accesses', { n: s.peers.filter(W.active).length }) : '' }); } catch { /* ohne Wächter-Liste */ } }
    if (this.ctx.keeper && typeof this.ctx.keeper.note === 'function' && s.wantRunning) {
      try { this.ctx.keeper.note('vpn', { ok: !bad2.length, label: 'VPN (WireGuard)', text: bad2.length ? bad2.map((i) => i.title).join(' · ') : this.t('Accesses, address and port forwarding are up to date.') }); } catch { /* ohne Selbstwartung */ }
    }
    if (expired.length || news.length) this.broadcast({ type: 'vpn' });
    return { issues };
  }
}

module.exports = { VpnService, OWNER };
