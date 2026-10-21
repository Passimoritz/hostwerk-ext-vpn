import { useEffect, useState } from 'react';
import { Shield, Plus, Play, Square, RotateCcw, Settings2, QrCode, Download, Copy, Pencil, Trash2, KeyRound, Router as RouterIcon, Users, ExternalLink, Wand2, Network } from 'lucide-react';
import { get, post, put, del, useApi, on } from '@hostwerk/api';
import { Btn, Seg, Field, Modal, Empty, Loading, Callout, InfoTip, Switch, toast, confirmDialog } from '@hostwerk/ui';
import { t } from '@hostwerk/i18n';
import './style.css';

/*
 * VPN-Zugang: WireGuard-Zustand mit Start/Stopp (Administrator-Abfrage nur nach Rückfrage), Zugänge je Person/Gerät mit
 * Konfiguration und QR-Code, Einstellungen, Tailscale-Status. Texte sind Englisch; Deutsch kommt aus locales/de.json.
 */
const enc = encodeURIComponent;
const copy = async (text, what) => { try { await navigator.clipboard.writeText(text); toast.success(t('{what} copied', { what: t(what) })); } catch { toast.error('Could not copy'); } };
const ago = (ms) => {
  if (!ms) return t('not connected yet');
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 180) return t('connected right now');
  if (s < 3600) return t('last seen {n} min ago', { n: Math.round(s / 60) });
  return t('last seen {time}', { time: new Date(ms).toLocaleString() });
};

/* ---------------- Zugang anlegen / ändern ---------------- */
function PeerForm({ peer, team, onClose, onSaved }) {
  const isNew = !peer;
  const members = useApi(isNew && team ? '/vpn/members' : null, [], { live: false, poll: false });
  const [f, setF] = useState({ person: peer ? peer.person : '', device: peer ? peer.device : '', member: '' });
  const pickMember = (id) => { const m = (members.data || []).find((x) => x.id === id); setF({ ...f, member: id, person: m ? m.name : f.person }); };
  const save = async () => {
    try {
      const r = isNew ? await post('/vpn/peers', { person: f.person, device: f.device, member: f.member || undefined }) : await put(`/vpn/peers/${enc(peer.id)}`, { person: f.person, device: f.device });
      toast.success(isNew ? 'Access created – now hand over the configuration or QR code.' : 'Saved');
      onSaved(r); onClose();
    } catch (e) { toast.error(e); }
  };
  return (
    <Modal title={isNew ? 'New access' : t('Access for {name}', { name: peer.person })} onClose={onClose} footer={<><Btn onClick={onClose}>Cancel</Btn><Btn className="primary" disabled={!f.person.trim()} onClick={save}>Save</Btn></>}>
      <div className="stack">
        {isNew && team && (members.data || []).length > 0 && (
          <Field label="Team member" hint="Optional – links the access to a member of “Team & roles”.">
            <select className="select" value={f.member} onChange={(e) => pickMember(e.target.value)}>
              <option value="">No team member</option>
              {members.data.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
            </select>
          </Field>
        )}
        <Field label="Person"><input className="input" value={f.person} onChange={(e) => setF({ ...f, person: e.target.value })} placeholder="e.g. Lena" autoFocus /></Field>
        <Field label="Device" hint="One access per device – e.g. phone and laptop separately."><input className="input" value={f.device} onChange={(e) => setF({ ...f, device: e.target.value })} placeholder="e.g. phone" /></Field>
      </div>
    </Modal>
  );
}

/* ---------------- Konfiguration + QR-Code ---------------- */
function ConfigView({ peer, onClose }) {
  const c = useApi(`/vpn/peers/${enc(peer.id)}/config`, [], { live: false, poll: false });
  const download = () => {
    const url = URL.createObjectURL(new Blob([c.data.text], { type: 'text/plain' }));
    const a = document.createElement('a'); a.href = url; a.download = c.data.file; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };
  return (
    <Modal title={t('Configuration for {name}', { name: peer.device ? `${peer.person} – ${peer.device}` : peer.person })} onClose={onClose} footer={<Btn onClick={onClose}>Close</Btn>}>
      {c.error ? <Callout kind="warn">{c.error}</Callout> : !c.data ? <Loading /> : (
        <div className="stack">
          <div className="vpn-qr-wrap">
            <img className="vpn-qr" alt={t('QR code with the WireGuard configuration')} src={`data:image/svg+xml;charset=utf-8,${enc(c.data.qr || '')}`} />
            <div className="stack small">
              <b>On the phone</b>
              <span className="muted">Open the WireGuard app → “+” → “Scan from QR code”.</span>
              <b>On a computer</b>
              <span className="muted">Download the file and import it in WireGuard (“Import tunnel from file”).</span>
              <div className="row-tight">
                <Btn className="sm primary" icon={Download} onClick={download}>Download</Btn>
                <Btn className="sm" icon={Copy} onClick={() => copy(c.data.text, 'Configuration')}>Copy</Btn>
              </div>
            </div>
          </div>
          <Callout kind="warn" dismissible={false}>The configuration contains the private key of this device. Pass it on only to this person – best in person or over a secure messenger.</Callout>
        </div>
      )}
    </Modal>
  );
}

/* ---------------- Einstellungen ---------------- */
function SettingsForm({ st, onClose, onSaved }) {
  const [f, setF] = useState({ ...st.settings, port: String(st.settings.port), keepalive: String(st.settings.keepalive) });
  const set = (k, v) => setF({ ...f, [k]: v });
  const suggest = async () => {
    try { const r = await get('/vpn/endpoint-suggestion'); if (r.endpoint) set('endpoint', r.endpoint); else toast.error('No public address found – enter your DynDNS name or domain.'); } catch (e) { toast.error(e); }
  };
  const save = async () => {
    try { onSaved(await put('/vpn/settings', { ...f, port: Number(f.port), keepalive: Number(f.keepalive) })); toast.success('Saved'); onClose(); } catch (e) { toast.error(e); }
  };
  return (
    <Modal title="VPN settings" onClose={onClose} footer={<><Btn onClick={onClose}>Cancel</Btn><Btn className="primary" onClick={save}>Save</Btn></>}>
      <div className="stack">
        <Field label="Address from outside" hint="Name or IP address under which devices reach this PC from the internet – best a DynDNS name or your domain.">
          <div className="row-tight">
            <input className="input mono grow" value={f.endpoint} onChange={(e) => set('endpoint', e.target.value)} placeholder="home.example.com" />
            {st.router && <Btn className="sm" icon={Wand2} title="Take the DynDNS name or public address from “Router & port forwarding”" onClick={suggest}>Suggest</Btn>}
          </div>
        </Field>
        <div className="grid grid-2">
          <Field label="UDP port" hint="Standard 51820 – this one port is all the router has to forward."><input className="input" inputMode="numeric" value={f.port} onChange={(e) => set('port', e.target.value)} /></Field>
          <Field label="VPN network" hint="Private network for the VPN; this PC gets .1"><input className="input mono" value={f.subnet} onChange={(e) => set('subnet', e.target.value)} /></Field>
        </div>
        <Field label="What devices reach">
          <Seg options={[{ id: 'host', label: 'Only this PC' }, ...(st.lanOk ? [{ id: 'lan', label: 'This PC and the home network' }] : [])]} value={f.scope} onChange={(v) => set('scope', v)} />
        </Field>
        {f.scope === 'lan' && <Field label="Home network" hint="e.g. 192.168.178.0/24 – Hostwerk switches on forwarding while the tunnel runs."><input className="input mono" value={f.lanSubnet} onChange={(e) => set('lanSubnet', e.target.value)} placeholder="192.168.178.0/24" /></Field>}
        {!st.lanOk && <p className="small muted">On Windows devices reach only this PC – that is enough for game servers, websites and file shares running here.</p>}
        <div className="grid grid-2">
          <Field label="DNS for devices (optional)" hint="e.g. 1.1.1.1 – empty = devices keep their own"><input className="input mono" value={f.dns} onChange={(e) => set('dns', e.target.value)} /></Field>
          <Field label="Keep-alive (seconds)" hint="Keeps the connection open behind mobile networks; 0 = off"><input className="input" inputMode="numeric" value={f.keepalive} onChange={(e) => set('keepalive', e.target.value)} /></Field>
        </div>
      </div>
    </Modal>
  );
}

/* ---------------- WireGuard-Zustand ---------------- */
function WireGuardCard({ st, reload, setData, openSettings }) {
  const wg = st.wireguard;
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
  const forward = async () => {
    try { const r = await post('/vpn/forward'); toast.success(t('UDP port {port} is forwarded in the router.', { port: r.port })); } catch (e) { toast.error(e); }
  };
  if (!wg.supported || !wg.installed) {
    const g = wg.guide || { steps: [] };
    return (
      <div className="card">
        <div className="card-head"><Shield size={16} /><h3>WireGuard</h3><span className="badge warn">{wg.supported ? 'not installed' : 'not supported here'}</span></div>
        <div className="card-body stack">
          <ol className="vpn-steps">{g.steps.map((s) => <li key={s}>{s}</li>)}</ol>
          {g.command && <div className="row-tight"><code className="grow ellipsis">{g.command}</code><Btn className="xs ghost icon" icon={Copy} title="Copy" aria-label="Copy" onClick={() => copy(g.command, 'Command')} /></div>}
          <div className="row-tight">
            <a className="btn sm" href={g.url} target="_blank" rel="noreferrer"><ExternalLink size={14} /> wireguard.com/install</a>
            <Btn className="sm ghost" icon={RotateCcw} onClick={() => reload()}>Check again</Btn>
          </div>
          <p className="small muted">You can already create accesses – the configurations work as soon as the tunnel runs.</p>
        </div>
      </div>
    );
  }
  return (
    <div className="card">
      <div className="card-head">
        <Shield size={16} /><h3>WireGuard</h3>
        <span className={`badge ${wg.running ? 'ok' : ''}`}>{wg.running ? 'running' : 'stopped'}</span>
        <InfoTip pop title="Why a VPN?">Instead of forwarding a port in the router for every server, only the WireGuard port is open. Friends with an access reach everything on this PC through it – everyone else sees nothing.</InfoTip>
        <div className="right row-tight">
          {wg.running ? <Btn className="sm" icon={Square} onClick={() => act(false)}>Stop</Btn> : <Btn className="sm primary" icon={Play} disabled={!st.peers.some((p) => p.enabled)} title={st.peers.some((p) => p.enabled) ? 'Asks for administrator rights' : 'Add an access first'} onClick={() => act(true)}>Start</Btn>}
        </div>
      </div>
      <div className="card-body stack">
        {st.needsRestart && <Callout kind="warn" dismissible={false} title="Restart needed">Accesses or settings changed while the tunnel was running. <Btn className="xs" icon={RotateCcw} onClick={restart}>Restart now</Btn></Callout>}
        {!st.settings.endpoint && <Callout kind="info" dismissible={false} title="Address from outside is missing">Devices need a name or IP address to find this PC. <Btn className="xs" icon={Settings2} onClick={openSettings}>Enter it</Btn></Callout>}
        <div className="vpn-facts small">
          <span className="muted">This PC in the VPN</span><code>{st.serverAddress}</code>
          <span className="muted">Reachable at</span><code>{st.settings.endpoint ? `${st.settings.endpoint}:${st.settings.port}` : '—'}</code>
          <span className="muted">Server key</span><code className="ellipsis" title={st.serverPublicKey}>{st.serverPublicKey}</code>
        </div>
        <div className="row-tight">
          {st.router ? <Btn className="sm" icon={RouterIcon} onClick={forward}>{t('Forward UDP port {port} in the router', { port: st.settings.port })}</Btn> : <span className="small muted">{t('Forward UDP port {port} in your router to this PC – the extension “Router & port forwarding” can do it with one click.', { port: st.settings.port })}</span>}
        </div>
      </div>
    </div>
  );
}

/* ---------------- Tailscale ---------------- */
function TailscaleCard({ ts }) {
  return (
    <div className="card">
      <div className="card-head"><Network size={16} /><h3>Tailscale</h3>{ts.installed && <span className={`badge ${ts.running ? 'ok' : 'warn'}`}>{ts.running ? 'connected' : ts.state}</span>}
        <InfoTip pop title="Tailscale">An alternative without any port forwarding: every device signs in to Tailscale and they find each other. Hostwerk only shows the status – you manage Tailscale in its own app.</InfoTip>
      </div>
      <div className="card-body small stack">
        {!ts.installed ? (
          <>
            <span className="muted">Not installed. If you prefer Tailscale: install it on this PC and on every device, sign in with the same account – done.</span>
            <a className="btn sm vpn-fit" href="https://tailscale.com/download" target="_blank" rel="noreferrer"><ExternalLink size={14} /> tailscale.com/download</a>
          </>
        ) : ts.running ? (
          <div className="vpn-facts">
            <span className="muted">This PC</span><code>{ts.dnsName || ts.name}</code>
            <span className="muted">Address</span><code>{(ts.ips || []).join(', ')}</code>
            {ts.tailnet && <><span className="muted">Network</span><span>{ts.tailnet}</span></>}
            <span className="muted">Devices</span><span>{t('{online} of {all} online', { online: ts.online, all: ts.peers })}</span>
          </div>
        ) : <span className="muted">Tailscale is installed but not connected – open the Tailscale app and sign in.</span>}
      </div>
    </div>
  );
}

/* ---------------- Seite ---------------- */
function VpnPage() {
  const s = useApi('/vpn', [], { live: false, poll: true });
  const [peer, setPeer] = useState(undefined);
  const [conf, setConf] = useState(null);
  const [settings, setSettings] = useState(false);
  useEffect(() => on('vpn', () => s.reload({ silent: true })), [s.reload]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!s.data) return s.error ? <div className="page"><Callout kind="err">{s.error}</Callout></div> : <Loading />;
  const st = s.data;
  const reload = () => s.reload({ silent: true });
  const remove = async (p) => {
    if (!(await confirmDialog({ title: t('Remove the access for “{name}”?', { name: p.person }), text: 'The device can no longer connect once the tunnel was restarted.', confirm: 'Remove', danger: true }))) return;
    try { await del(`/vpn/peers/${enc(p.id)}`); reload(); } catch (e) { toast.error(e); }
  };
  const rekey = async (p) => {
    if (!(await confirmDialog({ title: 'Make new keys?', text: 'For a lost or replaced device: the old configuration stops working, hand over the new one.', confirm: 'New keys' }))) return;
    try { await post(`/vpn/peers/${enc(p.id)}/rekey`); reload(); setConf(p); } catch (e) { toast.error(e); }
  };
  const toggle = async (p, on2) => { try { await put(`/vpn/peers/${enc(p.id)}`, { enabled: on2 }); reload(); } catch (e) { toast.error(e); } };
  return (
    <div className="page fade-in">
      <div className="page-head">
        <div>
          <h1><Shield /> VPN</h1>
          <p>WireGuard access for your devices and friends – one port forwarding instead of many, everything else stays private.</p>
        </div>
        <div className="actions">
          <Btn className="sm ghost" icon={Settings2} onClick={() => setSettings(true)}>Settings</Btn>
          <Btn className="sm primary" icon={Plus} onClick={() => setPeer(null)}>New access</Btn>
        </div>
      </div>
      <div className="vpn-grid">
        <div className="stack">
          <WireGuardCard st={st} reload={reload} setData={s.setData} openSettings={() => setSettings(true)} />
          <TailscaleCard ts={st.tailscale} />
        </div>
        <div className="card">
          <div className="card-head"><Users size={16} /><h3>Accesses</h3><div className="right"><Btn className="sm" icon={Plus} onClick={() => setPeer(null)}>New access</Btn></div></div>
          {!st.peers.length ? <Empty icon={KeyRound} title="No access yet" text="Create one access per person and device – Hostwerk makes the keys, the configuration file and a QR code for the phone." action={<Btn className="primary" icon={Plus} onClick={() => setPeer(null)}>New access</Btn>} /> : st.peers.map((p) => (
            <div key={p.id} className="list-item">
              <div className="grow vpn-peer">
                <div className="row-tight"><b className="ellipsis">{p.person}</b>{p.device && <span className="muted small ellipsis">{p.device}</span>}{p.member && <span className="badge accent">team</span>}{!p.enabled && <span className="badge">off</span>}</div>
                <div className="small muted"><code>{p.address}</code> · {st.wireguard.running ? ago(p.lastHandshake) : t('created {date}', { date: new Date(p.created).toLocaleDateString() })}</div>
              </div>
              <Switch checked={p.enabled} label={p.enabled ? t('Switch off access for {name}', { name: p.person }) : t('Switch on access for {name}', { name: p.person })} onChange={(v) => toggle(p, v)} />
              <Btn className="xs" icon={QrCode} onClick={() => setConf(p)}>Configuration</Btn>
              <Btn className="xs ghost icon" icon={Pencil} title="Change" aria-label="Change" onClick={() => setPeer(p)} />
              <Btn className="xs ghost icon" icon={KeyRound} title="New keys" aria-label="New keys" onClick={() => rekey(p)} />
              <Btn className="xs ghost icon" icon={Trash2} title="Remove" aria-label="Remove" onClick={() => remove(p)} />
            </div>
          ))}
        </div>
      </div>
      {peer !== undefined && <PeerForm peer={peer} team={st.team} onClose={() => setPeer(undefined)} onSaved={reload} />}
      {conf && <ConfigView peer={conf} onClose={() => setConf(null)} />}
      {settings && <SettingsForm st={st} onClose={() => setSettings(false)} onSaved={(d) => s.setData(d)} />}
    </div>
  );
}

export default {
  pages: { main: VpnPage },
};
