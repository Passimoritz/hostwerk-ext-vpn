![VPN access](banner.svg)

# VPN access

WireGuard access for your devices and friends – set up step by step (name, device, QR code or file with the right
guide), per access “home only”, “all traffic through home” or only certain services, with an end date and lock. Runs
maintenance-free: keeps the address and the router forwarding up to date, locks expired accesses, checks connections
and updates and reports problems in one go. Plus Tailscale (with Headscale), ZeroTier and NetBird at a glance.

[Deutsch](README.de.md) · An official [Hostwerk](https://github.com/Passimoritz/hostwerk-public) extension (SDK 2.7, native extension)

## What it does

- **Where:** Go live → Make reachable → VPN and the dashboard tile – no own sidebar entry since 1.2.0; the full page stays under Extensions → Open
- **State at the top:** running or off, address from outside, port in the router, WireGuard version, what runs by itself
  – and findings with a button that fixes them (start, forward, settings …)
- **New access in four steps:** who → which device (Android, iPhone/iPad, Windows, Mac, Linux) → what it may reach and
  for how long → QR code or file with the steps for exactly that device
- **Accesses at a glance:** who, device, reach, last connected, data received/sent, end date, on/off, lock, new keys
- **Reach per access:** *Home only* (this PC, on Linux also the home network), *All traffic through home* (Linux:
  forwarding and NAT, DNS set for the device) or *Only certain services* (ports of your Hostwerk services – Linux via
  iptables, Windows via firewall rules under the same administrator prompt)
- WireGuard keys are made in Hostwerk (X25519 plus a preshared key) – no command line needed; team members from
  “Team & roles” get their own access
- **Other ways:** Tailscale with its devices, exit node and subnet router (commands to copy), Headscale as your own
  server, ZeroTier and NetBird – recognised and shown read-only, with an honest comparison

## Maintenance-free

Every 15 minutes (and on *Check everything now*) Hostwerk does by itself what would otherwise need you:

| What | How |
|---|---|
| Accesses with an end date | locked when it has passed – and taken out of the running tunnel if Hostwerk has the rights (`wg set`, e.g. as system service); otherwise “Restart needed” |
| Address from outside | *DynDNS of the router*: follows the name of “Router & port forwarding”. *My own domain*: keeps the A/AAAA entry of e.g. `vpn.example.com` on your current IP through “DNS management”. A fixed IP as address: an IP change is reported |
| Port forwarding | the UDP port is forwarded through “Router & port forwarding” with the owner `vpn` while the VPN runs, moved with a port change, repaired when it is gone and removed when you stop the VPN |
| Connection type | carrier NAT and DS-Lite are recognised – with DS-Lite the VPN works over IPv6, without IPv4 and IPv6 the page recommends Tailscale/ZeroTier/NetBird |
| Updates | Windows: daily look at the official list (`download.wireguard.com/windows-client/latest.sig`, what WireGuard's own updater reads) – hint with `winget upgrade WireGuard.WireGuard`. Linux: version shown, updates come with your packages |
| Connections | “last connected” and data are remembered; nothing connected for a day after the start or a stopped tunnel that should run becomes a finding |
| Key age (optional) | reminder after 6, 12 or 24 months |

New problems arrive as **one** notification (own switch under Settings → Notifications, Hostwerk 2.12+), the state is in
the watcher list (Go live → Watchers) and in self-maintenance. Hints alone never send a notification.
Never automatic: starting, stopping and new keys – they need you (administrator prompt, new file for the device).

## How it works

1. **New access** – the wizard asks for the address from outside if it is missing (*Suggest* takes the DynDNS name or
   public address from “Router & port forwarding”).
2. **Start.** Hostwerk asks first and explains the administrator prompt; only then does Windows set up the tunnel service
   (`wireguard.exe /installtunnelservice`) or Linux run `wg-quick up` through pkexec. *Stop* works the same way.
3. Hand over the QR code or file – the page shows the steps for the device type.

## Security

- Private keys are sealed with Hostwerk's secret key (`config/secret.key`, AES-256-GCM) and never appear in a list. The
  configuration of a device (with its private key) only comes when you open it.
- The file for WireGuard (`data/vpn/hostwerk.conf`, readable only by the owner) is written right before the start and
  deleted after stopping. Live changes pass the preshared key through a temporary file, never on the command line.
- *Lock* takes the access out of the tunnel; *New keys* makes the old configuration of a lost device worthless.
- “Home only” accesses cannot use the forwarding of “all traffic” accesses (FORWARD rule per access) – a device that
  widens its own AllowedIPs still reaches no more than allowed.

## For other extensions: the service `vpn`

`await host.use('vpn')` (or `host.ctx.vpn`): `status()`, `peers()`, `addPeer({ person, device, member, platform, reach,
services, expires })`, `removePeer(id)`, `config(id)` → `{ file, text, qr, platform }`. Starting and stopping stay on
this page because they need the user's confirmation.

## Limits

- Windows: through the VPN only this PC is reachable; *All traffic through home* needs Linux.
- *Only certain services* on Windows needs Hostwerk 2.12 or newer (one administrator prompt for tunnel and firewall).
- Restart = stop + start, so administrator rights are asked for twice. Live changes without a restart only work when
  Hostwerk may run `wg set` (e.g. as system service, or Linux with the rights for it).
- Handshakes (“last connected”) need `wg show` – without administrator rights Windows does not answer; the WireGuard
  app shows them then.
- ZeroTier often only gives its status with administrator rights – then the page says so.
- Hostwerk creates no accounts with Tailscale, ZeroTier or NetBird and changes nothing there.

## Install

In Hostwerk: **Extensions → Discover** and click “Install”.

Native extensions run as part of Hostwerk (own server and interface part). That is why Hostwerk installs them only from the official catalog (with checksum) or in developer mode.

## Data

`data/vpn/state.json` – settings, accesses, maintenance state (last connected, forwarding, name, findings); private keys sealed with Hostwerk's secret key (`config/secret.key`). `data/vpn/hostwerk.conf` only exists while the tunnel is being started/runs. Removing the extension deletes nothing – stop the tunnel first.

## Develop

```bash
node --test tests/*.test.js          # tests (system, router, DNS and fetch are fakes – nothing is changed)
node build-native.js .               # build the interface (sdk/build-native.js from hostwerk-public)
node check.js . --strict             # the same check as the catalog (sdk/check.js)
```

Interface in `ui/src`, server part in `server/` (`maint.js` = maintenance rules, `wgconf.js` = files and firewall
rules, `system.js` = programs). Texts in the code are English, German is in `locales/de.json`.

## License

MIT
