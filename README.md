![VPN access](banner.svg)

# VPN access

WireGuard access for your devices and friends – one port forwarding instead of many: create keys, configuration and QR code for the phone, access per person (team members too), start and stop the WireGuard service. With a guide if WireGuard is missing, and the Tailscale status if you use that already.

[Deutsch](README.de.md) · An official [Hostwerk](https://github.com/Passimoritz/hostwerk-public) extension (SDK 2.7, native extension)

## What it does

- WireGuard keys are made in Hostwerk (X25519) – no command line needed
- Configuration file and QR code for the WireGuard app on phones
- Access per person and device, linked to members of “Team & roles” if you like
- Start and stop the WireGuard service: Windows tunnel service (asks for administrator rights first), Linux wg-quick
- Detects whether WireGuard is installed and shows how to install it
- Tailscale: shows the status and a short guide if it is installed
- One UDP port forwarding through “Router & port forwarding” with one click

## How it works

1. **Settings → Address from outside:** a DynDNS name or your domain (with “Router & port forwarding” installed,
   *Suggest* takes it from there).
2. **Forward one UDP port** (standard 51820) in the router to this PC – with the router extension in one click.
3. **New access** per person and device. Hostwerk makes the keys (X25519 plus a preshared key) and shows a QR code for
   the WireGuard app and a `.conf` file for computers.
4. **Start.** Hostwerk asks first and explains the administrator prompt; only then does Windows set up the tunnel service
   (`wireguard.exe /installtunnelservice`) or Linux run `wg-quick up` through pkexec. *Stop* works the same way.

Devices reach **only this PC** (`10.66.66.1` by default) – enough for game servers, websites and file shares that run
here. On Linux, *This PC and the home network* switches on forwarding and NAT while the tunnel runs.

Changes to accesses or settings while the tunnel runs are marked with *Restart needed* – Hostwerk never starts anything
with administrator rights by itself.

**Tailscale:** if it is installed, the page shows its status (connected, addresses, devices online). Hostwerk only reads
`tailscale status --json` and changes nothing there.

## Security

- Private keys are sealed with Hostwerk’s secret key (`config/secret.key`, AES-256-GCM) and never appear in lists. The
  configuration of a device (with its private key) is only sent when you open it.
- The file WireGuard needs (`data/vpn/hostwerk.conf`, readable by the owner only) is written right before starting and
  deleted after stopping.
- *New keys* makes the old configuration of a lost device useless (after a restart of the tunnel).

## For other extensions: the service `vpn`

`await host.use('vpn')` (or `host.ctx.vpn`): `status()`, `peers()`, `addPeer({ person, device, member })`,
`removePeer(id)`, `config(id)` → `{ file, text, qr }`. Starting and stopping stay on this page because they need the
user’s confirmation.

## Limits

- Windows: only this PC is reachable through the VPN (no forwarding into the home network).
- Restart = stop + start, so administrator rights are asked for twice.
- Handshakes (“last seen”) need `wg show` – without administrator rights Windows does not answer, then the list shows
  no time.
- The router extension has no public “remember this forwarding” function yet; the VPN adds its entry to the router’s
  list of own forwardings so automatic mode keeps it.

## Install

In Hostwerk: **Extensions → Discover** and click “Install”.

Native extensions run as part of Hostwerk (own server and interface part). That is why Hostwerk only installs them from the official catalogue (with checksum) or in developer mode.

## Data

`data/vpn/state.json` – settings and accesses; private keys sealed with Hostwerk’s secret key (`config/secret.key`). `data/vpn/hostwerk.conf` is only written while the tunnel is started (WireGuard needs it as a file). Removing the extension deletes nothing – stop the tunnel first.

## Develop

```bash
node --test tests/*.test.js          # tests
node build-native.js .               # build the interface (sdk/build-native.js from hostwerk-public)
node check.js . --strict             # same check as the catalogue (sdk/check.js)
```

Interface source in `ui/src`, server part in `server/`. Texts in the code are English, German is in `locales/de.json`.

## License

MIT
