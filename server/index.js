'use strict';
/*
 * VPN-Zugang – Server-Teil (SDK 2.7, native Erweiterung). Stellt "vpn" für Hostwerk und andere Erweiterungen bereit.
 *   GET    /api/vpn                       → Zustand: WireGuard/Tailscale, Einstellungen, Zugänge (ohne private Schlüssel)
 *   PUT    /api/vpn/settings              → { endpoint, port, subnet, dns, scope, lanSubnet, keepalive }
 *   GET    /api/vpn/endpoint-suggestion   → DynDNS-Name oder öffentliche IPv4 (Router-Erweiterung)
 *   GET    /api/vpn/members               → Mitglieder aus „Team & Rollen“
 *   POST   /api/vpn/peers                 → { person, device, member }
 *   PUT    /api/vpn/peers/:id             → { person, device, enabled }
 *   POST   /api/vpn/peers/:id/rekey
 *   DELETE /api/vpn/peers/:id
 *   GET    /api/vpn/peers/:id/config      → { file, text, qr } – enthält den privaten Schlüssel des Geräts
 *   POST   /api/vpn/start | stop          → { confirm: true } – Administrator-Abfrage von Windows bzw. pkexec
 *   POST   /api/vpn/forward               → UDP-Port über „Router & Portfreigaben“ freigeben
 */
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { VpnService } = require('./service');
const { WgSystem } = require('./system');

let svc = null;

/** Programm ausführen und Exit-Code + Ausgabe liefern (nur lesende Abfragen: sc query, wg show, tailscale status). */
const run = (cmd, args) => new Promise((resolve) => {
  try {
    execFile(cmd, args, { windowsHide: true, timeout: 8000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: String(stdout || '') }));
  } catch { resolve({ code: 1, stdout: '' }); }
});

function activate(host) {
  const { ctx } = host;
  const platform = host.core('platform');
  const qrcode = host.lib('qrcode');
  const system = new WgSystem({
    run,
    elevated: (cmd, args) => platform.elevated(cmd, args),
    exists: (p) => { try { return fs.existsSync(p); } catch { return false; } },
    which: (n) => platform.which(n),
  });
  svc = new VpnService({
    dir: path.join(ctx.paths.data, 'vpn'), secrets: host.core('secrets'), system, ctx, pkgHint: platform.pkgHint, broadcast: host.broadcast,
    qr: (text) => qrcode.toString(text, { type: 'svg', errorCorrectionLevel: 'M', margin: 1 }),
  });
  host.provide('vpn', svc);
  const r = host.router;
  const wrap = (fn) => async (req, res) => {
    try { await fn(req, res); } catch (e) {
      // Ohne grafische Abfrage (z. B. Linux ohne Desktop): den Befehl zum Selbst-Eintippen als Hilfe mitschicken
      const hint = e.manual ? { title: host.t('Do it by hand'), text: host.t('If no prompt appeared, run this command yourself:'), steps: [e.manual] } : null;
      throw host.error(e.status || 500, e.message, e.vars, hint ? { hint } : undefined);
    }
  };
  const id = (req) => String(req.params.id);
  r.get('/vpn', wrap(async (req, res) => res.json(await svc.status())));
  r.put('/vpn/settings', wrap(async (req, res) => res.json(await svc.saveSettings(req.body || {}))));
  r.get('/vpn/endpoint-suggestion', wrap(async (req, res) => res.json(await svc.suggestEndpoint())));
  r.get('/vpn/members', wrap(async (req, res) => res.json(svc.members())));
  r.post('/vpn/peers', wrap(async (req, res) => res.json(svc.addPeer(req.body || {}))));
  r.put('/vpn/peers/:id', wrap(async (req, res) => res.json(svc.updatePeer(id(req), req.body || {}))));
  r.post('/vpn/peers/:id/rekey', wrap(async (req, res) => res.json(svc.rekeyPeer(id(req)))));
  r.delete('/vpn/peers/:id', wrap(async (req, res) => { svc.removePeer(id(req)); res.json({ ok: true }); }));
  r.get('/vpn/peers/:id/config', wrap(async (req, res) => { res.set('Cache-Control', 'no-store'); res.json(await svc.config(id(req))); }));
  r.post('/vpn/start', wrap(async (req, res) => res.json(await svc.start(req.body || {}))));
  r.post('/vpn/stop', wrap(async (req, res) => res.json(await svc.stop(req.body || {}))));
  r.post('/vpn/forward', wrap(async (req, res) => res.json(await svc.forward())));
}

function deactivate() { svc = null; }

module.exports = { activate, deactivate };
