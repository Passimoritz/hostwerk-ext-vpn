import { useEffect, useState } from 'react';
import { Check, ArrowLeft, ArrowRight, Home, Globe2, Boxes, Wand2 } from 'lucide-react';
import { get, post, put, useApi } from '@hostwerk/api';
import { Btn, Field, Modal, Seg, Callout, InfoTip, Loading, toast } from '@hostwerk/ui';
import { t } from '@hostwerk/i18n';
import { PLATFORMS, ConfigBody, loadServices, enc } from './common';

/*
 * Zugang anlegen in vier Schritten: Wer → welches Gerät → was darf der Zugang (und wie lange) → einrichten (QR/Datei).
 * Dieselben Felder ändert AccessForm für einen bestehenden Zugang.
 */
const DAY = 86400000;
const ENDS = [{ id: 'never', label: 'No end' }, { id: 'day', label: '1 day' }, { id: 'week', label: '1 week' }, { id: 'month', label: '1 month' }, { id: 'date', label: 'Until …' }];
const endsAt = (k, date) => (k === 'day' ? Date.now() + DAY : k === 'week' ? Date.now() + 7 * DAY : k === 'month' ? Date.now() + 30 * DAY : k === 'date' && date ? new Date(`${date}T23:59:59`).getTime() : null);
const dateOf = (ms) => { if (!ms) return ''; const d = new Date(ms); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };

/** Gerätearten als Kacheln (Tastatur: Tab + Leertaste/Enter, aria-pressed) */
function PlatformPick({ value, onChange }) {
  return (
    <div className="vpn-platforms" role="group" aria-label={t('Device type')}>
      {Object.entries(PLATFORMS).map(([id, P]) => (
        <button key={id} type="button" className={`vpn-platform ${value === id ? 'on' : ''}`} aria-pressed={value === id} onClick={() => onChange(id)}>
          <P.icon size={22} aria-hidden="true" /><span>{t(P.label)}</span>
        </button>
      ))}
    </div>
  );
}

/** Was darf der Zugang? „nur zu Hause“, „alles über zu Hause“, „nur bestimmte Dienste“ – plus Ablauf. */
function ReachPick({ st, f, set }) {
  const [svcs, setSvcs] = useState(null);
  useEffect(() => { if (f.reach === 'services' && !svcs) loadServices().then(setSvcs).catch(() => setSvcs([])); }, [f.reach]); // eslint-disable-line react-hooks/exhaustive-deps -- einmal laden, wenn gebraucht
  const home = st.settings.scope === 'lan' ? 'This PC and your home network' : 'Only this PC';
  const opts = [
    { id: 'home', icon: Home, title: 'Home only', text: t('{what} – everything else on the device goes the usual way.', { what: t(home) }), ok: true },
    { id: 'full', icon: Globe2, title: 'All traffic through home', text: 'The whole internet traffic of the device goes through your connection – handy on public Wi-Fi.', ok: st.fullOk, why: 'Needs Linux on this PC (forwarding and NAT). On Windows choose “Home only”.' },
    { id: 'services', icon: Boxes, title: 'Only certain services', text: 'The device reaches only the ports you pick below – nothing else on this PC.', ok: st.servicesOk },
  ];
  const toggle = (s) => { const has = f.services.some((x) => x.port === s.port); set('services', has ? f.services.filter((x) => x.port !== s.port) : [...f.services, { port: s.port, name: s.name }]); };
  return (
    <div className="stack">
      <div className="vpn-reach" role="radiogroup" aria-label={t('What the access may reach')}>
        {opts.map((o) => (
          <button key={o.id} type="button" role="radio" aria-checked={f.reach === o.id} disabled={!o.ok} className={`vpn-reach-opt ${f.reach === o.id ? 'on' : ''}`} onClick={() => set('reach', o.id)} title={o.ok ? undefined : o.why}>
            <o.icon size={18} aria-hidden="true" />
            <span className="stack vpn-gap-0"><b className="small">{o.title}</b><span className="tiny muted">{o.ok ? o.text : o.why}</span></span>
          </button>
        ))}
      </div>
      {f.reach === 'services' && (
        <Field label="Services">
          {!svcs ? <Loading text="Loading services …" /> : !svcs.length ? <span className="small muted">No service with a port yet – create one in Hostwerk first.</span> : (
            <div className="vpn-svc-list">
              {svcs.map((s) => <label key={s.port} className="check small"><input type="checkbox" checked={f.services.some((x) => x.port === s.port)} onChange={() => toggle(s)} />{s.name} <span className="muted mono">{s.port}</span></label>)}
            </div>
          )}
        </Field>
      )}
      <Field label="How long">
        <Seg value={f.end} onChange={(v) => set('end', v)} options={ENDS} />
      </Field>
      {f.end === 'date' && <Field label="Last day"><input className="input vpn-date" type="date" min={dateOf(Date.now())} value={f.date} onChange={(e) => set('date', e.target.value)} /></Field>}
      {f.end !== 'never' && <span className="tiny muted">After that Hostwerk locks the access by itself – you can unlock it any time.</span>}
    </div>
  );
}

/** Fehlt die Adresse von außen, fragt der Assistent sie gleich mit ab (sonst lässt sich keine Konfiguration bauen). */
function EndpointAsk({ st, value, onChange }) {
  const suggest = async () => {
    try { const r = await get('/vpn/endpoint-suggestion'); if (r.endpoint) onChange(r.endpoint); else toast.error('No public address found – enter your DynDNS name or domain.'); } catch (e) { toast.error(e); }
  };
  return (
    <Field label="Address from outside" hint="Name or IP address under which devices reach this PC – best a DynDNS name or your domain.">
      <div className="row-tight">
        <input className="input mono grow" value={value} onChange={(e) => onChange(e.target.value)} placeholder="home.example.com" />
        {st.router && <Btn className="sm" icon={Wand2} title="Take the DynDNS name or public address from “Router & port forwarding”" onClick={suggest}>Suggest</Btn>}
      </div>
    </Field>
  );
}

const STEPS = ['Who', 'Device', 'Access', 'Set up'];

export function NewAccess({ st, onClose, onDone }) {
  const [step, setStep] = useState(0);
  const [f, setF] = useState({ person: '', device: '', member: '', platform: '', reach: 'home', services: [], end: 'never', date: '', endpoint: st.settings.endpoint || '' });
  const [created, setCreated] = useState(null);
  const [busy, setBusy] = useState(false);
  const members = useApi(st.team ? '/vpn/members' : null, [], { live: false, poll: false });
  const set = (k, v) => setF((x) => ({ ...x, [k]: v }));
  const pickMember = (id) => { const m = (members.data || []).find((x) => x.id === id); setF((x) => ({ ...x, member: id, person: m ? m.name : x.person })); };
  const canNext = step === 0 ? !!f.person.trim() : step === 1 ? !!f.platform : step === 2 ? (f.reach !== 'services' || f.services.length > 0) && (f.end !== 'date' || !!f.date) && !!f.endpoint.trim() : true;
  const create = async () => {
    setBusy(true);
    try {
      if (f.endpoint.trim() !== (st.settings.endpoint || '')) await put('/vpn/settings', { endpoint: f.endpoint.trim() });
      const p = await post('/vpn/peers', { person: f.person, device: f.device, member: f.member || undefined, platform: f.platform, reach: f.reach, services: f.services, expires: endsAt(f.end, f.date) });
      setCreated(p); setStep(3); onDone();
    } catch (e) { toast.error(e); }
    setBusy(false);
  };
  const footer = (
    <>
      {step > 0 && step < 3 && <Btn icon={ArrowLeft} onClick={() => setStep(step - 1)}>Back</Btn>}
      <span className="grow" />
      {step < 2 && <Btn className="primary" icon={ArrowRight} disabled={!canNext} onClick={() => setStep(step + 1)}>Next</Btn>}
      {step === 2 && <Btn className="primary" icon={Check} busy={busy} disabled={!canNext} onClick={create}>Create access</Btn>}
      {step === 3 && <Btn className="primary" icon={Check} onClick={onClose}>Done</Btn>}
    </>
  );
  return (
    <Modal title="New access" subtitle={created ? t('For {name}', { name: created.device ? `${created.person} – ${created.device}` : created.person }) : null} size="wide" onClose={onClose} footer={footer}>
      <ol className="vpn-wizard-steps" aria-label={t('Steps')}>
        {STEPS.map((s, i) => <li key={s} className={i === step ? 'now' : i < step ? 'done' : ''} aria-current={i === step ? 'step' : undefined}><span className="vpn-step-n" aria-hidden="true">{i < step ? <Check size={12} /> : i + 1}</span>{s}</li>)}
      </ol>
      {step === 0 && (
        <div className="stack">
          {st.team && (members.data || []).length > 0 && (
            <Field label="Team member" hint="Optional – links the access to a member of “Team & roles”.">
              <select className="select" value={f.member} onChange={(e) => pickMember(e.target.value)}>
                <option value="">No team member</option>
                {members.data.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
              </select>
            </Field>
          )}
          <Field label="Name"><input className="input" value={f.person} onChange={(e) => set('person', e.target.value)} placeholder="e.g. Lena" autoFocus /></Field>
          <Field label="Device name (optional)" hint="One access per device – e.g. phone and laptop separately."><input className="input" value={f.device} onChange={(e) => set('device', e.target.value)} placeholder="e.g. phone" /></Field>
        </div>
      )}
      {step === 1 && <div className="stack"><span className="small muted">Which device will use the access? Hostwerk then shows the right way to set it up.</span><PlatformPick value={f.platform} onChange={(v) => set('platform', v)} /></div>}
      {step === 2 && (
        <div className="stack">
          <ReachPick st={st} f={f} set={set} />
          {!st.settings.endpoint && <EndpointAsk st={st} value={f.endpoint} onChange={(v) => set('endpoint', v)} />}
        </div>
      )}
      {step === 3 && created && (
        <div className="stack">
          <ConfigBody peer={created} />
          {!st.wireguard.running && <Callout kind="info" dismissible={false}>The VPN is not running yet – start it on the VPN page once the devices are ready.</Callout>}
        </div>
      )}
    </Modal>
  );
}

/** Bestehenden Zugang ändern: Name, Gerät, Reichweite, Ablauf. */
export function AccessForm({ st, peer, onClose, onSaved }) {
  const [f, setF] = useState({ person: peer.person, device: peer.device, platform: peer.platform, reach: peer.reach, services: peer.services || [], end: peer.expires ? 'date' : 'never', date: dateOf(peer.expires), endpoint: st.settings.endpoint });
  const set = (k, v) => setF((x) => ({ ...x, [k]: v }));
  const save = async () => {
    try {
      const r = await put(`/vpn/peers/${enc(peer.id)}`, { person: f.person, device: f.device, platform: f.platform, reach: f.reach, services: f.services, expires: endsAt(f.end, f.date) });
      toast.success('Saved'); onSaved(r); onClose();
    } catch (e) { toast.error(e); }
  };
  const changesFile = f.reach !== peer.reach;
  return (
    <Modal title={t('Access for {name}', { name: peer.person })} size="wide" onClose={onClose} footer={<><Btn onClick={onClose}>Cancel</Btn><Btn className="primary" disabled={!f.person.trim() || (f.reach === 'services' && !f.services.length) || (f.end === 'date' && !f.date)} onClick={save}>Save</Btn></>}>
      <div className="stack">
        <div className="grid grid-2">
          <Field label="Name"><input className="input" value={f.person} onChange={(e) => set('person', e.target.value)} /></Field>
          <Field label="Device name (optional)"><input className="input" value={f.device} onChange={(e) => set('device', e.target.value)} /></Field>
        </div>
        <Field label="Device type"><PlatformPick value={f.platform} onChange={(v) => set('platform', v)} /></Field>
        <ReachPick st={st} f={f} set={set} />
        {changesFile && <Callout kind="info" dismissible={false} title="New file for the device">What the device sends through the VPN is in its configuration – hand over the configuration again after saving.<InfoTip pop title="Why?">WireGuard decides on the device which addresses go through the tunnel (AllowedIPs). This PC also limits it, so an old file cannot reach more than allowed.</InfoTip></Callout>}
      </div>
    </Modal>
  );
}
