![VPN-Zugang](banner.svg)

# VPN-Zugang

WireGuard-Zugänge für deine Geräte und Freunde – statt vieler Portfreigaben nur eine: Schlüssel erzeugen, Konfiguration und QR-Code fürs Handy, Zugänge je Person (auch für Team-Mitglieder), WireGuard-Dienst starten und stoppen. Mit Anleitung, falls WireGuard fehlt, und Tailscale-Status, falls du das schon nutzt.

[English](README.md) · Eine offizielle [Hostwerk](https://github.com/Passimoritz/hostwerk-public) Erweiterung (SDK 2.7, native Erweiterung)

## Was sie kann

- WireGuard-Schlüssel entstehen in Hostwerk (X25519) – ohne Kommandozeile
- Konfigurationsdatei und QR-Code für die WireGuard-App auf dem Handy
- Zugänge je Person und Gerät, auf Wunsch mit Mitgliedern aus „Team & Rollen“ verknüpft
- WireGuard-Dienst starten und stoppen: Windows-Tunneldienst (fragt vorher nach Administratorrechten), Linux wg-quick
- Erkennt, ob WireGuard installiert ist, und zeigt, wie man es installiert
- Tailscale: zeigt Status und eine kurze Anleitung, falls installiert
- Eine UDP-Portfreigabe über „Router & Portfreigaben“ mit einem Klick

## So geht’s

1. **Einstellungen → Adresse von außen:** ein DynDNS-Name oder deine Domain (mit „Router & Portfreigaben“ übernimmt
   *Vorschlagen* sie von dort).
2. **Einen UDP-Port freigeben** (Standard 51820) im Router für diesen PC – mit der Router-Erweiterung per Klick.
3. **Neuer Zugang** je Person und Gerät. Hostwerk erzeugt die Schlüssel (X25519 plus PresharedKey) und zeigt einen
   QR-Code für die WireGuard-App und eine `.conf`-Datei für Computer.
4. **Starten.** Hostwerk fragt vorher und erklärt die Administrator-Abfrage; erst dann richtet Windows den Tunneldienst
   ein (`wireguard.exe /installtunnelservice`) bzw. Linux führt `wg-quick up` über pkexec aus. *Stoppen* genauso.

Geräte erreichen **nur diesen PC** (standardmäßig `10.66.66.1`) – das reicht für Spiele-Server, Webseiten und
Dateifreigaben, die hier laufen. Unter Linux schaltet *Dieser PC und das Heimnetz* Weiterleitung und NAT ein, solange der
Tunnel läuft.

Ändern sich Zugänge oder Einstellungen, während der Tunnel läuft, steht dort *Neustart nötig* – Hostwerk startet nie von
selbst etwas mit Administratorrechten.

**Tailscale:** Ist es installiert, zeigt die Seite den Status (verbunden, Adressen, Geräte online). Hostwerk liest nur
`tailscale status --json` und ändert dort nichts.

## Sicherheit

- Private Schlüssel sind mit Hostwerks Geheimschlüssel versiegelt (`config/secret.key`, AES-256-GCM) und stehen in keiner
  Liste. Die Konfiguration eines Geräts (mit seinem privaten Schlüssel) kommt nur, wenn du sie öffnest.
- Die Datei für WireGuard (`data/vpn/hostwerk.conf`, nur für den Besitzer lesbar) entsteht direkt vor dem Start und wird
  nach dem Stoppen gelöscht.
- *Neue Schlüssel* macht die alte Konfiguration eines verlorenen Geräts wertlos (nach einem Neustart des Tunnels).

## Für andere Erweiterungen: der Dienst `vpn`

`await host.use('vpn')` (oder `host.ctx.vpn`): `status()`, `peers()`, `addPeer({ person, device, member })`,
`removePeer(id)`, `config(id)` → `{ file, text, qr }`. Starten und Stoppen bleiben auf dieser Seite, weil sie die
Bestätigung des Nutzers brauchen.

## Grenzen

- Windows: Übers VPN ist nur dieser PC erreichbar (keine Weiterleitung ins Heimnetz).
- Neustart = Stoppen + Starten, deshalb wird zweimal nach Administratorrechten gefragt.
- Handschläge („zuletzt verbunden“) brauchen `wg show` – ohne Administratorrechte antwortet Windows nicht, dann steht in
  der Liste keine Zeit.
- Die Router-Erweiterung hat noch keine öffentliche Funktion „diese Freigabe merken“; das VPN trägt seinen Eintrag in die
  Liste ihrer eigenen Freigaben ein, damit der Automatikmodus ihn behält.

## Installieren

In Hostwerk: **Erweiterungen → Entdecken** und „Installieren“ klicken.

Native Erweiterungen laufen als Teil von Hostwerk (eigener Server- und Oberflächen-Teil). Deshalb installiert Hostwerk sie nur aus dem offiziellen Katalog (mit Prüfsumme) oder im Entwickler-Modus.

## Daten

`data/vpn/state.json` – Einstellungen und Zugänge; private Schlüssel mit Hostwerks Geheimschlüssel (`config/secret.key`) versiegelt. `data/vpn/hostwerk.conf` entsteht nur beim Starten des Tunnels (WireGuard braucht sie als Datei). Entfernen der Erweiterung löscht nichts – vorher den Tunnel stoppen.

## Entwickeln

```bash
node --test tests/*.test.js          # Tests
node build-native.js .               # Oberfläche bauen (sdk/build-native.js aus hostwerk-public)
node check.js . --strict             # dieselbe Prüfung wie der Katalog (sdk/check.js)
```

Oberfläche in `ui/src`, Server-Teil in `server/`. Texte im Code sind Englisch, Deutsch steht in `locales/de.json`.

## Lizenz

MIT
