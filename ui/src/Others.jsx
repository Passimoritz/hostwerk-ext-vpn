import { Network, ExternalLink, Copy, RotateCcw, Server, Waypoints, Bird, Shield } from 'lucide-react';
import { useApi, openExternal } from '@hostwerk/api';
import { Btn, InfoTip, Loading, Callout } from '@hostwerk/ui';
import { t, pl } from '@hostwerk/i18n';
import { copy, ago } from './common';

/*
 * Andere Wege ins Heimnetz – ehrlich eingeordnet und nur lesend: Hostwerk erkennt Tailscale (auch mit Headscale),
 * ZeroTier und NetBird, zeigt Zustand und Geräte und erklärt die nächsten Schritte. Konten legt Hostwerk nirgends an.
 */
function Cmd({ cmd }) {
  return <div className="row-tight vpn-cmd"><code className="grow ellipsis">{cmd}</code><Btn className="xs ghost icon" icon={Copy} title="Copy" aria-label="Copy" onClick={() => copy(cmd, 'Command')} /></div>;
}
const Badge = ({ x, on = 'connected', off = 'not connected' }) => (!x.installed ? <span className="badge">not installed</span> : x.needsAdmin ? <span className="badge warn">status needs admin rights</span> : <span className={`badge ${x.running || x.online ? 'ok' : 'warn'}`}>{x.running || x.online ? t(on) : t(off)}</span>);

function TailscaleCard({ ts, hs, win }) {
  return (
    <div className="card">
      <div className="card-head"><Network size={16} /><h3>Tailscale</h3><Badge x={ts} />{ts.headscale && <span className="badge accent">Headscale</span>}
        <InfoTip pop title="Tailscale">Every device signs in to the same Tailscale network and they find each other – no port forwarding, works behind carrier NAT too. The free plan is enough for home use. Hostwerk only reads the status; you manage Tailscale in its own app.</InfoTip>
      </div>
      <div className="card-body small stack">
        {!ts.installed ? (
          <>
            <span className="muted">Good choice when your connection cannot be reached from outside (carrier NAT) or you do not want to forward any port.</span>
            <div><Btn className="sm" icon={ExternalLink} onClick={() => openExternal('https://tailscale.com/download')}>tailscale.com/download</Btn></div>
          </>
        ) : !ts.running ? <span className="muted">Tailscale is installed but not connected – open the Tailscale app and sign in.</span> : (
          <>
            <div className="vpn-facts">
              <span className="muted">This PC</span><code>{ts.dnsName || ts.name}</code>
              <span className="muted">Address</span><code>{(ts.ips || []).join(', ')}</code>
              {ts.tailnet && <><span className="muted">Network</span><span>{ts.tailnet}</span></>}
              {ts.controlUrl && ts.headscale && <><span className="muted">Own server</span><code className="ellipsis">{ts.controlUrl}</code></>}
              <span className="muted">Devices</span><span>{t('{online} of {all} online', { online: ts.online, all: ts.peers })}</span>
            </div>
            {ts.devices && ts.devices.length > 0 && (
              <table className="table vpn-table"><thead><tr><th>Device</th><th>System</th><th>Address</th><th>Status</th></tr></thead><tbody>
                {ts.devices.slice(0, 20).map((d) => (
                  <tr key={d.name + (d.ips[0] || '')}>
                    <td className="ellipsis">{d.name}{d.exitNode && <span className="badge accent vpn-gap-l">exit node in use</span>}{!d.exitNode && d.exitNodeOption && <span className="badge vpn-gap-l">offers exit node</span>}</td>
                    <td className="muted">{d.os}</td>
                    <td className="mono">{d.ips[0] || '–'}</td>
                    <td>{d.online ? <span className="badge ok">online</span> : <span className="muted">{d.lastSeen ? ago(d.lastSeen) : t('offline')}</span>}</td>
                  </tr>
                ))}
              </tbody></table>
            )}
            <div className="stack vpn-gap-1">
              <b className="row-tight">This PC as exit node <InfoTip pop title="Exit node">Devices can send all their internet traffic through this PC – like “All traffic through home” with WireGuard. Afterwards allow it once in the Tailscale admin console.</InfoTip></b>
              {ts.advertises && ts.advertises.exitNode ? <span className="badge ok vpn-fit">offered</span> : <Cmd cmd="tailscale set --advertise-exit-node" />}
              <b className="row-tight">Share your home network <InfoTip pop title="Subnet router">Devices in Tailscale reach your printer, NAS and router at home through this PC. Replace the network with yours and allow the route in the admin console.</InfoTip></b>
              {ts.advertises && ts.advertises.routes.length ? <span className="small">{t('Shared: {nets}', { nets: ts.advertises.routes.join(', ') })}</span> : <Cmd cmd={`tailscale set --advertise-routes=192.168.178.0/24${win ? '' : ' # Linux: sysctl -w net.ipv4.ip_forward=1 first'}`} />}
            </div>
          </>
        )}
      </div>
      <div className="card-body small stack vpn-sub">
        <b className="row-tight"><Server size={14} aria-hidden="true" />Headscale – your own Tailscale server <span className="badge">optional</span></b>
        <span className="muted">Headscale replaces the Tailscale sign-in with a server you run yourself (Linux). Clients stay the normal Tailscale apps. Worth it if you want no account anywhere – but you look after the server yourself.</span>
        {hs && hs.installed ? <span className="badge ok vpn-fit">{t('Headscale {v} is installed on this PC', { v: hs.version || '' })}</span> : <div><Btn className="sm ghost" icon={ExternalLink} onClick={() => openExternal('https://headscale.net/stable/')}>headscale.net</Btn></div>}
        {(ts.headscale || (hs && hs.installed)) && <Cmd cmd="tailscale up --login-server https://headscale.example.com" />}
      </div>
    </div>
  );
}

function ZeroTierCard({ z }) {
  return (
    <div className="card">
      <div className="card-head"><Waypoints size={16} /><h3>ZeroTier</h3><Badge x={z} on="online" off="offline" />
        <InfoTip pop title="ZeroTier">A virtual network across the internet like Tailscale – you join a network by its ID and allow the device in the ZeroTier web console. No port forwarding needed.</InfoTip>
      </div>
      <div className="card-body small stack">
        {!z.installed ? <><span className="muted">Alternative to Tailscale, with free networks up to a few devices.</span><div><Btn className="sm" icon={ExternalLink} onClick={() => openExternal('https://www.zerotier.com/download/')}>zerotier.com/download</Btn></div></>
          : z.needsAdmin ? <span className="muted">ZeroTier is installed. Its status can only be read with administrator rights – open the ZeroTier app to see the networks.</span>
            : (
              <>
                <div className="vpn-facts"><span className="muted">Node ID</span><code>{z.address}</code>{z.version && <><span className="muted">Version</span><span>{z.version}</span></>}</div>
                {z.networks.length ? z.networks.map((n) => <div key={n.id} className="row-tight vpn-wrap"><b>{n.name || n.id}</b><span className={`badge ${n.status === 'OK' ? 'ok' : 'warn'}`}>{n.status === 'OK' ? t('connected') : n.status}</span><code>{n.ips.join(', ')}</code></div>)
                  : <><span className="muted">Not in any network yet. Join one with its network ID:</span><Cmd cmd="zerotier-cli join <network-id>" /></>}
              </>
            )}
      </div>
    </div>
  );
}

function NetBirdCard({ n }) {
  return (
    <div className="card">
      <div className="card-head"><Bird size={16} /><h3>NetBird</h3><Badge x={n} />
        <InfoTip pop title="NetBird">Open-source network on top of WireGuard with its own sign-in – as a cloud service or self-hosted. Like Tailscale, it needs no port forwarding.</InfoTip>
      </div>
      <div className="card-body small stack">
        {!n.installed ? <><span className="muted">Open-source alternative to Tailscale, also self-hostable.</span><div><Btn className="sm" icon={ExternalLink} onClick={() => openExternal('https://netbird.io/download')}>netbird.io/download</Btn></div></>
          : !n.running ? <><span className="muted">NetBird is installed but not connected.</span><Cmd cmd="netbird up" /></>
            : <div className="vpn-facts"><span className="muted">Address</span><code>{n.ip}</code>{n.fqdn && <><span className="muted">Name</span><code>{n.fqdn}</code></>}<span className="muted">Devices</span><span>{t('{online} of {all} online', { online: n.online, all: n.peers })}</span>{n.management && <><span className="muted">Server</span><code className="ellipsis">{n.management}</code></>}</div>}
      </div>
    </div>
  );
}

export default function Others({ st }) {
  const o = useApi('/vpn/others', [], { live: false, poll: false });
  if (o.error) return <Callout kind="warn" dismissible={false}>{o.error}</Callout>;
  if (!o.data) return <Loading text="Looking for other VPNs …" />;
  const d = o.data;
  const found = ['tailscale', 'zerotier', 'netbird'].filter((k) => d[k] && d[k].installed).length;
  return (
    <div className="stack">
      <div className="card">
        <div className="card-head"><Shield size={16} /><h3>Which way fits?</h3><span className="badge">{pl(found, '{n} found on this PC', '{n} found on this PC')}</span>
          <div className="right"><Btn className="sm ghost icon" icon={RotateCcw} title="Look again" aria-label="Look again" onClick={() => o.reload()} /></div>
        </div>
        <div className="card-body small vpn-compare">
          <div><b>WireGuard (this page)</b> <span className="badge ok">recommended</span><p className="muted">Your own server, no account anywhere, fastest. Needs one UDP port forwarding – does not work behind carrier NAT without IPv6.</p></div>
          <div><b>Tailscale · ZeroTier · NetBird</b><p className="muted">No port forwarding, works behind every connection. Every device signs in to the service (or your own Headscale/NetBird server).</p></div>
          {st.net && st.net.cgnat && !st.net.v6 && <Callout kind="warn" dismissible={false} title="Your connection">No own public IPv4 and no IPv6 – WireGuard cannot be reached from outside here. One of these services is the way to go.</Callout>}
        </div>
      </div>
      <TailscaleCard ts={d.tailscale} hs={d.headscale} win={d.platform === 'win32'} />
      <div className="grid grid-2">
        <ZeroTierCard z={d.zerotier} />
        <NetBirdCard n={d.netbird} />
      </div>
    </div>
  );
}
