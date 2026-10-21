import { useEffect, useState } from 'react';
import { Shield, ShieldCheck, ShieldAlert, ShieldOff, Plus, Play, Square, RotateCcw, Settings2, QrCode, Copy, Pencil, Trash2, KeyRound, Router as RouterIcon, Users, ExternalLink, Wand2, Lock, LockOpen, Stethoscope, Network, CalendarClock } from 'lucide-react';
import { get, post, put, del, useApi, on, openExternal } from '@hostwerk/api';
import { Btn, Seg, Field, Modal, Empty, Loading, Callout, InfoTip, Switch, toast, confirmDialog } from '@hostwerk/ui';
import { t, pl } from '@hostwerk/i18n';
import { enc, copy, ago, recent, bytes, platformOf, ConfigBody } from './common';
import { NewAccess, AccessForm } from './Wizard';
import Others from './Others';
import './style.css';

/*
 * VPN-Zugang: oben der Zustand des VPN-Dienstes (läuft/aus, Adresse, Freigabe, was von selbst läuft, Befunde), darunter
 * die Zugänge (wer, Gerät, zuletzt verbunden, Datenmenge, an/aus/sperren) – neue über einen geführten Ablauf – und
 * „Andere Wege“ (Tailscale/Headscale, ZeroTier, NetBird). Administrator-Abfragen nur nach Rückfrage.
 * Texte sind Englisch; Deutsch kommt aus locales/de.json.
 */

/* ---------------- Konfiguration (bestehender Zugang) ---------------- */
function ConfigView({ peer, onClose }) {
  return (
    <Modal title={t('Configuration for {name}', { name: peer.device ? `${peer.person} – ${peer.device}` : peer.person })} size="wide" onClose={onClose} footer={<Btn onClick={onClose}>Close</Btn>}>
      <ConfigBody peer={peer} />
    </Modal>
  );
}

/* ---------------- Einstellungen ---------------- */
function SettingsForm({ st, onClose, onSaved }) {
  const [f, setF] = useState({ ...st.settings, port: String(st.settings.port), keepalive: String(st.settings.keepalive) });
  const set = (k, v) => setF((x) => ({ ...x, [k]: v }));
  const suggest = async () => {
    try { const r = await get('/vpn/endpoint-suggestion'); if (r.endpoint) set('endpoint', r.endpoint); else toast.error('No public address found – enter your DynDNS name or domain.'); } catch (e) { toast.error(e); }
  };
  const save = async () => {
    try { onSaved(await put('/vpn/settings', { ...f, port: Number(f.port), keepalive: Number(f.keepalive), rotateMonths: Number(f.rotateMonths) })); toast.success('Saved'); onClose(); } catch (e) { toast.error(e); }
  };
  const modes = [
    { id: 'manual', label: 'Enter it myself' },
    ...(st.router ? [{ id: 'dyndns', label: 'DynDNS of the router' }] : []),
    ...(st.dnsExt ? [{ id: 'dns', label: 'My own domain' }] : []),
  ];
  return (
    <Modal title="VPN settings" size="wide" onClose={onClose} footer={<><Btn onClick={onClose}>Cancel</Btn><Btn className="primary" onClick={save}>Save</Btn></>}>
      <div className="stack">
        <Field label="How devices find this PC">
          <Seg options={modes} value={f.endpointMode} onChange={(v) => setF((x) => ({ ...x, endpointMode: v, endpoint: v === 'dyndns' ? (st.dyndns || '') : x.endpoint }))} />
        </Field>
        {f.endpointMode === 'manual' && (
          <Field label="Address from outside" hint="Name or IP address under which devices reach this PC from the internet – a name keeps working when your IP changes.">
            <div className="row-tight">
              <input className="input mono grow" value={f.endpoint} onChange={(e) => set('endpoint', e.target.value)} placeholder="home.example.com" />
              {st.router && <Btn className="sm" icon={Wand2} title="Take the DynDNS name or public address from “Router & port forwarding”" onClick={suggest}>Suggest</Btn>}
            </div>
          </Field>
        )}
        {f.endpointMode === 'dyndns' && (st.dyndns ? <span className="small">{t('Devices use {name} – the router extension keeps it up to date.', { name: st.dyndns })}</span> : <Callout kind="info" dismissible={false}>Set up DynDNS in “Router & port forwarding” first (Go live → Router).</Callout>)}
        {f.endpointMode === 'dns' && (
          <Field label="Name at your domain" hint="e.g. vpn.example.com – Hostwerk sets its A/AAAA entry at your DNS provider and updates it when your IP changes.">
            <input className="input mono" value={f.endpoint} onChange={(e) => set('endpoint', e.target.value)} placeholder="vpn.example.com" />
          </Field>
        )}
        <div className="grid grid-2">
          <Field label="UDP port" hint="Standard 51820 – this one port is all the router has to forward."><input className="input" inputMode="numeric" value={f.port} onChange={(e) => set('port', e.target.value)} /></Field>
          <Field label="VPN network" hint="Private network for the VPN; this PC gets .1"><input className="input mono" value={f.subnet} onChange={(e) => set('subnet', e.target.value)} /></Field>
        </div>
        <Field label="“Home only” means">
          <Seg options={[{ id: 'host', label: 'Only this PC' }, ...(st.lanOk ? [{ id: 'lan', label: 'This PC and the home network' }] : [])]} value={f.scope} onChange={(v) => set('scope', v)} />
        </Field>
        {f.scope === 'lan' && <Field label="Home network" hint="e.g. 192.168.178.0/24 – Hostwerk switches on forwarding while the tunnel runs."><input className="input mono" value={f.lanSubnet} onChange={(e) => set('lanSubnet', e.target.value)} placeholder="192.168.178.0/24" /></Field>}
        {!st.lanOk && <span className="small muted">On Windows devices reach only this PC – that is enough for game servers, websites and file shares running here.</span>}
        <div className="grid grid-2">
          <Field label="DNS for devices (optional)" hint="e.g. 1.1.1.1 – empty = devices keep their own"><input className="input mono" value={f.dns} onChange={(e) => set('dns', e.target.value)} /></Field>
          <Field label="Keep-alive (seconds)" hint="Keeps the connection open behind mobile networks; 0 = off"><input className="input" inputMode="numeric" value={f.keepalive} onChange={(e) => set('keepalive', e.target.value)} /></Field>
        </div>
        <h3 className="vpn-h">Runs by itself</h3>
        {st.router && <label className="check small"><input type="checkbox" checked={f.autoForward} onChange={(e) => set('autoForward', e.target.checked)} />Forward the UDP port in the router while the VPN runs (and repair it)</label>}
        <label className="check small"><input type="checkbox" checked={f.updateCheck} onChange={(e) => set('updateCheck', e.target.checked)} />Check daily whether a new WireGuard version is out (official source)</label>
        <Field label="Remind me to renew keys">
          <select className="select" value={String(f.rotateMonths)} onChange={(e) => set('rotateMonths', Number(e.target.value))}>
            <option value="0">Never</option><option value="6">After 6 months</option><option value="12">After a year</option><option value="24">After two years</option>
          </select>
        </Field>
      </div>
    </Modal>
  );
}

/* ---------------- Zustand oben ---------------- */
function adminActions(st, setData, reload) {
  const confirmAdmin = (start) => confirmDialog({
    title: start ? 'Start the VPN?' : 'Stop the VPN?',
    text: st.platform === 'win32'
      ? (start ? 'WireGuard sets up the tunnel as a Windows service. Windows now asks for administrator rights – confirm the prompt.' : 'WireGuard removes the tunnel service. Windows asks for administrator rights.')
      : (start ? 'wg-quick sets up the tunnel. Linux now asks for your password (administrator rights).' : 'wg-quick removes the tunnel. Linux asks for your password.'),
    confirm: start ? 'Start' : 'Stop',
  });
  const act = async (start) => {
    if (!(await confirmAdmin(start))) return;
    try { setData(await post(`/vpn/${start ? 'start' : 'stop'}`, { confirm: true })); toast.success(start ? 'VPN started' : 'VPN stopped'); } catch (e) { toast.error(e); reload(); }
  };
  const restart = async () => {
    if (!(await confirmDialog({ title: 'Restart the VPN?', text: 'The tunnel is stopped and started again so the changes apply. Administrator rights are asked for twice.', confirm: 'Restart' }))) return;
    try { await post('/vpn/stop', { confirm: true }); setData(await post('/vpn/start', { confirm: true })); toast.success('VPN restarted'); } catch (e) { toast.error(e); reload(); }
  };
  return { start: () => act(true), stop: () => act(false), restart };
}

function InstallCard({ wg, reload }) {
  const g = wg.guide || { steps: [] };
  return (
    <div className="card">
      <div className="card-head"><ShieldOff size={16} /><h3>WireGuard is missing</h3><span className="badge warn">{wg.supported ? 'not installed' : 'not supported here'}</span></div>
      <div className="card-body stack">
        <ol className="vpn-steps">{g.steps.map((s) => <li key={s}>{s}</li>)}</ol>
        {g.command && <div className="row-tight vpn-cmd"><code className="grow ellipsis">{g.command}</code><Btn className="xs ghost icon" icon={Copy} title="Copy" aria-label="Copy" onClick={() => copy(g.command, 'Command')} /></div>}
        <div className="row-tight">
          <Btn className="sm" icon={ExternalLink} onClick={() => openExternal(g.url)}>wireguard.com/install</Btn>
          <Btn className="sm ghost" icon={RotateCcw} onClick={() => reload()}>Check again</Btn>
        </div>
        <span className="small muted">You can already create accesses – the configurations work as soon as the tunnel runs.</span>
      </div>
    </div>
  );
}

function StatusPanel({ st, admin, openSettings, onCheck, checking }) {
  const wg = st.wireguard;
  const active = st.peers.filter((p) => p.enabled && !p.lock);
  const now = st.peers.filter((p) => recent(p.lastHandshake)).length;
  const errs = st.health.issues.filter((i) => i.level !== 'info').length;
  const state = !wg.running ? 'off' : errs ? 'warn' : 'on';
  const Icon = state === 'on' ? ShieldCheck : state === 'warn' ? ShieldAlert : Shield;
  const title = wg.running ? (errs ? t('VPN is running – {n} things need a look', { n: errs }) : t('VPN is running')) : st.wantRunning ? t('VPN is off – it should be running') : t('VPN is off');
  const sub = wg.running ? (wg.live ? pl(now, '{n} device connected right now', '{n} devices connected right now') + ` · ${pl(active.length, '{n} access', '{n} accesses')}` : pl(active.length, '{n} access', '{n} accesses')) : (active.length ? t('Start it so your {n} accesses work.', { n: active.length }) : t('Create an access first, then start the VPN.'));
  const fwd = st.forward;
  const auto = [
    { on: true, text: 'Locks expired accesses' },
    { on: st.settings.endpointMode !== 'manual', text: st.settings.endpointMode === 'dns' ? 'Keeps your name on the current IP' : 'Follows the DynDNS name' },
    { on: st.router && st.settings.autoForward, text: 'Keeps the port forwarded in the router' },
    { on: st.settings.updateCheck, text: 'Checks for WireGuard updates' },
    { on: true, text: 'Watches connections and reports problems once' },
  ].filter((a) => a.on);
  return (
    <section className={`card vpn-status vpn-st-${state}`} aria-label={t('State of the VPN')}>
      <div className="card-body vpn-status-row">
        <span className="vpn-status-ico" aria-hidden="true"><Icon size={26} /></span>
        <div className="grow vpn-min">
          <div className="vpn-status-title" role="status">{title}</div>
          <div className="small muted">{sub}</div>
        </div>
        <div className="row-tight vpn-wrap">
          <Btn className="sm ghost icon" icon={Stethoscope} busy={checking} title="Check everything now" aria-label="Check everything now" onClick={onCheck} />
          {st.needsRestart && <Btn className="sm" icon={RotateCcw} onClick={admin.restart}>Restart</Btn>}
          {wg.running ? <Btn className="sm" icon={Square} onClick={admin.stop}>Stop</Btn> : <Btn className="sm primary" icon={Play} disabled={!active.length} title={active.length ? 'Asks for administrator rights' : 'Add an access first'} onClick={admin.start}>Start</Btn>}
        </div>
      </div>
      <div className="vpn-tiles">
        <div className="vpn-tile">
          <span className="tiny muted">Address from outside</span>
          {st.settings.endpoint ? <code className="ellipsis" title={`${st.settings.endpoint}:${st.settings.port}`}>{st.settings.endpoint}:{st.settings.port}</code> : <button type="button" className="link-btn small" onClick={openSettings}>Enter it</button>}
          <span className="tiny muted">{st.settings.endpointMode === 'dns' ? (st.dnsState && st.dnsState.ok ? t('own domain, kept up to date') : t('own domain')) : st.settings.endpointMode === 'dyndns' ? t('DynDNS of the router') : t('entered by hand')}</span>
        </div>
        <div className="vpn-tile">
          <span className="tiny muted">Port in the router</span>
          <b className="small">{t('UDP {port}', { port: st.settings.port })}</b>
          <span className={`tiny ${fwd && fwd.state === 'failed' ? 'c-err' : 'muted'}`}>{!st.router ? t('forward it by hand') : !fwd || fwd.state === 'none' ? t('forwarded when the VPN runs') : fwd.state === 'ok' ? t('forwarded') : t('forwarding failed')}</span>
        </div>
        <div className="vpn-tile">
          <span className="tiny muted">This PC in the VPN</span>
          <code>{st.serverAddress}</code>
          <span className="tiny muted ellipsis" title={st.serverPublicKey}>{t('Key {k}…', { k: st.serverPublicKey.slice(0, 10) })}</span>
        </div>
        <div className="vpn-tile">
          <span className="tiny muted">WireGuard</span>
          <b className="small">{wg.version || (wg.installed ? t('installed') : t('missing'))}</b>
          <span className="tiny muted">{wg.latest && wg.version && wg.latest !== wg.version ? t('{v} available', { v: wg.latest }) : wg.version ? t('up to date') : ''}</span>
        </div>
      </div>
      <div className="vpn-auto small">
        <span className="muted">Runs by itself</span>
        {auto.map((a) => <span key={a.text} className="vpn-chip">{a.text}</span>)}
        <InfoTip pop title="Maintenance-free">Every 15 minutes Hostwerk checks the tunnel, the connections, the address from outside and the port forwarding. It repairs what it can by itself and sends one notification when something needs you. Starting, stopping and new keys stay your decision.</InfoTip>
      </div>
    </section>
  );
}

const ACTION_LABEL = { start: 'Start', settings: 'Settings', forward: 'Forward now', restart: 'Restart', others: 'Show alternatives', update: 'How to update', rekey: 'To the accesses', check: 'Check again' };
function Findings({ st, admin, openSettings, setTab, onCheck }) {
  const issues = st.health.issues || [];
  if (!issues.length) return null;
  const run = async (a) => {
    if (a === 'start') return admin.start();
    if (a === 'restart') return admin.restart();
    if (a === 'settings') return openSettings();
    if (a === 'others') return setTab('others');
    if (a === 'rekey') return setTab('accesses');
    if (a === 'check') return onCheck();
    if (a === 'update') return st.platform === 'win32' ? copy('winget upgrade WireGuard.WireGuard', 'Command') : openExternal('https://www.wireguard.com/install/');
    if (a === 'forward') { try { await post('/vpn/forward'); toast.success(t('UDP port {port} is forwarded in the router.', { port: st.settings.port })); onCheck(); } catch (e) { toast.error(e); } }
    return null;
  };
  return (
    <div className="stack vpn-findings">
      {issues.map((i) => (
        <Callout key={i.id} kind={i.level === 'err' ? 'err' : i.level === 'warn' ? 'warn' : 'info'} title={i.title} dismissible={false}>
          <span>{i.text}</span>{i.action && ACTION_LABEL[i.action] && <> <Btn className="xs" onClick={() => run(i.action)}>{ACTION_LABEL[i.action]}</Btn></>}
          {i.action === 'update' && st.platform === 'win32' && <span className="tiny muted vpn-block">winget upgrade WireGuard.WireGuard – or “Check for updates” in the WireGuard app</span>}
        </Callout>
      ))}
    </div>
  );
}

/* ---------------- Zugänge ---------------- */
const REACH_LABEL = { home: 'Home only', full: 'All traffic', services: 'Some services' };
function AccessList({ st, reload, onNew, onEdit, onConfig }) {
  const remove = async (p) => {
    if (!(await confirmDialog({ title: t('Remove the access for “{name}”?', { name: p.person }), text: 'The device can no longer connect. To give it access again, create a new one.', confirm: 'Remove', danger: true }))) return;
    try { await del(`/vpn/peers/${enc(p.id)}`); reload(); } catch (e) { toast.error(e); }
  };
  const rekey = async (p) => {
    if (!(await confirmDialog({ title: 'Make new keys?', text: 'For a lost or replaced device: the old configuration stops working, hand over the new one.', confirm: 'New keys' }))) return;
    try { const r = await post(`/vpn/peers/${enc(p.id)}/rekey`); reload(); onConfig(r); } catch (e) { toast.error(e); }
  };
  const lock = async (p, locked) => {
    if (locked && !(await confirmDialog({ title: t('Lock the access for “{name}”?', { name: p.person }), text: 'The device cannot connect until you unlock it. For a lost device, better make new keys.', confirm: 'Lock' }))) return;
    try { await put(`/vpn/peers/${enc(p.id)}`, { locked }); reload(); } catch (e) { toast.error(e); }
  };
  const toggle = async (p, v) => { try { await put(`/vpn/peers/${enc(p.id)}`, { enabled: v }); reload(); } catch (e) { toast.error(e); } };
  if (!st.peers.length) return <div className="card"><Empty icon={KeyRound} title="No access yet" text="Create one access per person and device – Hostwerk makes the keys and shows the QR code or file with the right steps." action={<Btn className="primary" icon={Plus} onClick={onNew}>New access</Btn>} /></div>;
  return (
    <div className="card">
      <div className="card-head"><Users size={16} /><h3>Accesses</h3><span className="badge">{st.peers.length}</span><div className="right"><Btn className="sm primary" icon={Plus} onClick={onNew}>New access</Btn></div></div>
      <div className="vpn-scroll">
        <table className="table vpn-table">
          <thead><tr><th>Who</th><th>Reach</th><th>Last connected</th><th>Data</th><th>Ends</th><th><span className="sr-only">On</span></th><th><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {st.peers.map((p) => {
              const P = platformOf(p.platform);
              const state = p.lock ? (p.lock.reason === 'expired' ? 'expired' : 'locked') : !p.enabled ? 'off' : null;
              return (
                <tr key={p.id} className={state ? 'vpn-row-dim' : ''}>
                  <td>
                    <div className="row-tight vpn-min">
                      <P.icon size={16} aria-label={t(P.label)} className="vpn-plat" />
                      <span className="stack vpn-gap-0 vpn-min">
                        <b className="ellipsis">{p.person}{p.member && <span className="badge accent vpn-gap-l">team</span>}</b>
                        <span className="tiny muted ellipsis">{p.device || t(P.label)} · <code>{p.address}</code></span>
                      </span>
                    </div>
                  </td>
                  <td className="small">{t(REACH_LABEL[p.reach] || p.reach)}{p.reach === 'services' && <span className="tiny muted vpn-block">{p.services.map((x) => x.name || x.port).join(', ')}</span>}</td>
                  <td className="small">{recent(p.lastHandshake) ? <span className="badge ok">connected</span> : <span className="muted">{ago(p.lastHandshake)}</span>}</td>
                  <td className="small mono" title={t('received / sent by this PC')}>{p.rx === null ? '–' : `↓ ${bytes(p.rx)} ↑ ${bytes(p.tx)}`}</td>
                  <td className="small">
                    {state === 'expired' ? <span className="badge warn">expired</span> : state === 'locked' ? <span className="badge err">locked</span> : p.expires ? <span className="row-tight"><CalendarClock size={12} aria-hidden="true" />{new Date(p.expires).toLocaleDateString()}</span> : <span className="muted">–</span>}
                    {p.rotationDue && <span className="badge vpn-gap-l" title={t('These keys are older than you wanted – make new ones.')}>keys due</span>}
                  </td>
                  <td>{!p.lock && <Switch checked={p.enabled} label={p.enabled ? t('Switch off access for {name}', { name: p.person }) : t('Switch on access for {name}', { name: p.person })} onChange={(v) => toggle(p, v)} />}</td>
                  <td className="actions">
                    <Btn className="xs ghost icon" icon={QrCode} title="Configuration" aria-label="Configuration" disabled={!!p.lock} onClick={() => onConfig(p)} />
                    <Btn className="xs ghost icon" icon={Pencil} title="Change" aria-label="Change" onClick={() => onEdit(p)} />
                    <Btn className="xs ghost icon" icon={KeyRound} title="New keys" aria-label="New keys" onClick={() => rekey(p)} />
                    {p.lock ? <Btn className="xs ghost icon" icon={LockOpen} title="Unlock" aria-label="Unlock" onClick={() => lock(p, false)} /> : <Btn className="xs ghost icon" icon={Lock} title="Lock" aria-label="Lock" onClick={() => lock(p, true)} />}
                    <Btn className="xs ghost icon" icon={Trash2} title="Remove" aria-label="Remove" onClick={() => remove(p)} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {st.wireguard.running && !st.wireguard.live && <div className="card-body tiny muted">“Last connected” and data appear when Hostwerk may read the tunnel (administrator rights, e.g. as system service) – otherwise the WireGuard app shows them.</div>}
    </div>
  );
}

/* ---------------- Seite ---------------- */
function VpnPage() {
  const s = useApi('/vpn', [], { live: false, poll: true });
  const [tab, setTab] = useState('accesses');
  const [wizard, setWizard] = useState(false);
  const [edit, setEdit] = useState(null);
  const [conf, setConf] = useState(null);
  const [settings, setSettings] = useState(false);
  const [checking, setChecking] = useState(false);
  useEffect(() => on('vpn', () => s.reload({ silent: true })), [s.reload]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!s.data) return s.error ? <div className="page"><Callout kind="err">{s.error}</Callout></div> : <Loading />;
  const st = s.data;
  const reload = () => s.reload({ silent: true });
  const admin = adminActions(st, s.setData, reload);
  const check = async () => { setChecking(true); try { s.setData(await post('/vpn/check')); } catch (e) { toast.error(e); } setChecking(false); };
  const wg = st.wireguard;
  return (
    <div className="page fade-in">
      <div className="page-head">
        <div>
          <h1><Shield /> VPN</h1>
          <p>Reach this PC from anywhere – one port forwarding instead of many, everything else stays private.</p>
        </div>
        <div className="actions">
          <Btn className="sm ghost" icon={Settings2} onClick={() => setSettings(true)}>Settings</Btn>
          <Btn className="sm primary" icon={Plus} onClick={() => setWizard(true)}>New access</Btn>
        </div>
      </div>
      <div className="stack">
        {wg.supported && wg.installed ? <StatusPanel st={st} admin={admin} openSettings={() => setSettings(true)} onCheck={check} checking={checking} /> : <InstallCard wg={wg} reload={reload} />}
        <Findings st={st} admin={admin} openSettings={() => setSettings(true)} setTab={setTab} onCheck={check} />
        <div className="sub-nav"><Seg value={tab} onChange={setTab} options={[{ id: 'accesses', label: 'Accesses', icon: Users }, { id: 'others', label: 'Other ways', icon: Network }]} /></div>
        {tab === 'accesses' && <AccessList st={st} reload={reload} onNew={() => setWizard(true)} onEdit={setEdit} onConfig={setConf} />}
        {tab === 'others' && <Others st={st} />}
        {tab === 'accesses' && st.router && !st.settings.autoForward && (
          <div className="row-tight small"><Btn className="sm ghost" icon={RouterIcon} onClick={async () => { try { const r = await post('/vpn/forward'); toast.success(t('UDP port {port} is forwarded in the router.', { port: r.port })); reload(); } catch (e) { toast.error(e); } }}>{t('Forward UDP port {port} in the router', { port: st.settings.port })}</Btn></div>
        )}
      </div>
      {wizard && <NewAccess st={st} onClose={() => setWizard(false)} onDone={reload} />}
      {edit && <AccessForm st={st} peer={edit} onClose={() => setEdit(null)} onSaved={reload} />}
      {conf && <ConfigView peer={conf} onClose={() => setConf(null)} />}
      {settings && <SettingsForm st={st} onClose={() => setSettings(false)} onSaved={(d) => s.setData(d)} />}
    </div>
  );
}

/** Übersichtskachel: läuft das VPN, wie viele Zugänge, wer ist gerade verbunden. */
function VpnTile() {
  const s = useApi('/vpn', [], { live: false, poll: true });
  if (!s.data) return s.error ? <div className="card-body small muted">{s.error}</div> : <div className="card-body"><Loading /></div>;
  const st = s.data;
  const active = st.peers.filter((p) => p.enabled && !p.lock);
  const now = st.peers.filter((p) => recent(p.lastHandshake));
  const errs = st.health.issues.filter((i) => i.level !== 'info');
  return (
    <a className="card-body stack vpn-tile-link" href="#/ext/vpn">
      <span className="row-tight"><span className={`vpn-dot ${!st.wireguard.running ? 'off' : errs.length ? 'warn' : 'on'}`} aria-hidden="true" /><b>{st.wireguard.running ? t('VPN is running') : t('VPN is off')}</b></span>
      <span className="small muted">{pl(active.length, '{n} access', '{n} accesses')}{st.wireguard.live ? ` · ${pl(now.length, '{n} connected', '{n} connected')}` : ''}</span>
      {now.slice(0, 3).map((p) => <span key={p.id} className="small ellipsis">{p.device ? `${p.person} – ${p.device}` : p.person}</span>)}
      {errs.slice(0, 2).map((i) => <span key={i.id} className="small c-warn ellipsis">{i.title}</span>)}
    </a>
  );
}

export default {
  pages: { main: VpnPage },
  slots: {
    // Seit Hostwerk 3.0 (SDK 3.2) ohne eigenen Seitenleisten-Eintrag ("nav": false) – die ganze Seite als Reiter im passenden Bereich;
    // Hostwerk blendet dabei ihren Titel aus (Reiter + Herkunftszeile sagen schon, was es ist), die Knöpfe bleiben
    // Livebetrieb → Erreichbar machen, hinter „Fernzugriff“
    'live.tabs': [{ id: 'vpn', title: 'VPN', icon: Shield, Component: VpnPage, group: 'erreichbar', after: 'fernzugriff', order: 40 }],
    'dashboard.tiles': [{ id: 'state', title: 'VPN', icon: Shield, size: 'third', Component: VpnTile }],
  },
};
