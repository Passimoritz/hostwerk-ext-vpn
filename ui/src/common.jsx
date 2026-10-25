import { useState } from 'react';
import { Smartphone, Tablet, Monitor, Laptop, TerminalSquare, HelpCircle, Download, Copy, ExternalLink } from 'lucide-react';
import { get, useApi, openExternal } from '@hostwerk/api';
import { Btn, Callout, Loading, toast } from '@hostwerk/ui';
import { t } from '@hostwerk/i18n';

/*
 * Gemeinsame Bausteine: Gerätearten mit Anleitung, Konfiguration (QR-Code bzw. Datei), Zahlen und Zeiten.
 * Texte sind Englisch; Deutsch kommt aus locales/de.json.
 */
export const enc = encodeURIComponent;
export const copy = async (text, what) => { try { await navigator.clipboard.writeText(text); toast.success(t('{what} copied', { what: t(what) })); } catch { toast.error('Could not copy'); } };

/** „vor 5 Minuten“ – letzter Handschlag (WireGuard meldet sich alle zwei Minuten, solange Verkehr da ist) */
export const ago = (ms) => {
  if (!ms) return t('never connected');
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 180) return t('connected right now');
  if (s < 3600) return t('{n} min ago', { n: Math.round(s / 60) });
  if (s < 86400) return t('{n} h ago', { n: Math.round(s / 3600) });
  return new Date(ms).toLocaleDateString();
};
export const recent = (ms) => !!ms && Date.now() - ms < 180000;

export function bytes(n) {
  if (n === null || n === undefined) return '–';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}

/** Gerätearten: Symbol, ob ein QR-Code passt, App und Schritte zum Einrichten */
export const PLATFORMS = {
  android: { label: 'Android', icon: Smartphone, qr: true, app: 'https://play.google.com/store/apps/details?id=com.wireguard.android', steps: ['Install the WireGuard app from the Play Store.', 'Tap “+” → “Scan from QR code” and point the camera at the code.', 'Switch the new tunnel on – done.'] },
  ios: { label: 'iPhone / iPad', icon: Tablet, qr: true, app: 'https://apps.apple.com/app/wireguard/id1441195209', steps: ['Install the WireGuard app from the App Store.', 'Tap “Add a tunnel” → “Create from QR code” and scan the code.', 'Allow the VPN configuration and switch the tunnel on.'] },
  windows: { label: 'Windows', icon: Monitor, qr: false, app: 'https://www.wireguard.com/install/', steps: ['Install WireGuard for Windows.', 'Download the file below and choose “Import tunnel(s) from file” in WireGuard.', 'Click “Activate”.'] },
  macos: { label: 'Mac', icon: Laptop, qr: false, app: 'https://apps.apple.com/app/wireguard/id1451685025', steps: ['Install WireGuard from the Mac App Store.', 'Download the file below and choose “Import tunnel(s) from file”.', 'Click “Activate” and allow the VPN configuration.'] },
  linux: { label: 'Linux', icon: TerminalSquare, qr: false, app: 'https://www.wireguard.com/install/', steps: ['Install the package wireguard-tools (or use the network settings of your desktop).', 'Download the file below and import it in the network settings (nmcli connection import type wireguard file …).', 'Or start it in the terminal with sudo wg-quick up and the file.'] },
  other: { label: 'Other device', icon: HelpCircle, qr: true, app: 'https://www.wireguard.com/install/', steps: ['Install a WireGuard app for this device (wireguard.com/install).', 'Scan the QR code or import the file.'] },
};
export const platformOf = (id) => PLATFORMS[id] || PLATFORMS.other;

/** Konfiguration eines Zugangs: QR-Code fürs Handy bzw. Datei für Computer – mit der passenden Anleitung. */
export function ConfigBody({ peer }) {
  const c = useApi(`/vpn/peers/${enc(peer.id)}/config`, [peer.id, peer.publicKey], { live: false, poll: false });
  const [showQr, setShowQr] = useState(null);
  if (c.error) return <Callout kind="warn" dismissible={false}>{c.error}</Callout>;
  if (!c.data) return <Loading text="Making the configuration …" />;
  const P = platformOf(peer.platform);
  const qr = showQr === null ? P.qr : showQr;
  const download = () => {
    const url = URL.createObjectURL(new Blob([c.data.text], { type: 'text/plain' }));
    const a = document.createElement('a'); a.href = url; a.download = c.data.file; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };
  return (
    <div className="stack">
      <div className="vpn-qr-wrap">
        {qr ? <img className="vpn-qr" alt={t('QR code with the WireGuard configuration')} src={`data:image/svg+xml;charset=utf-8,${enc(c.data.qr || '')}`} />
          : <div className="vpn-file"><Download size={28} aria-hidden="true" /><code className="ellipsis">{c.data.file}</code><Btn className="sm primary" icon={Download} onClick={download}>Download file</Btn></div>}
        <div className="stack small">
          <b className="row-tight"><P.icon size={16} aria-hidden="true" />{t('On {device}', { device: t(P.label) })}</b>
          <ol className="vpn-steps">{P.steps.map((s) => <li key={s}>{s}</li>)}</ol>
          <div className="row-tight vpn-wrap">
            <Btn className="sm" icon={ExternalLink} onClick={() => openExternal(P.app)}>Get the app</Btn>
            {qr ? <Btn className="sm" icon={Download} onClick={download}>Download file</Btn> : <Btn className="sm ghost" onClick={() => setShowQr(true)}>Show QR code</Btn>}
            <Btn className="sm ghost" icon={Copy} onClick={() => copy(c.data.text, 'Configuration')}>Copy</Btn>
          </div>
        </div>
      </div>
      <Callout kind="warn" dismissible={false}>The configuration contains the private key of this device. Pass it on only to this person – best in person or over a secure messenger.</Callout>
    </div>
  );
}

/** Dienste dieses PCs mit Port (für „nur bestimmte Dienste“) – aus Hostwerks Übersicht. */
export async function loadServices() {
  const o = await get('/overview');
  const out = [];
  const add = (xs, kind) => { for (const s of xs || []) if (s && Number.isInteger(s.port) && !out.some((x) => x.port === s.port)) out.push({ port: s.port, name: s.name || s.id, kind }); };
  add(o.web, 'web'); add(o.apps, 'app'); add(o.db, 'db');
  for (const k of Object.values(o.kinds || {})) add(k.items, k.kind); // Dienst-Arten der Erweiterungen (Minecraft, Spiele-Server …)
  return out;
}
