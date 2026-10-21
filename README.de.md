![VPN-Zugang](banner.svg)

# VPN-Zugang

WireGuard-Zugänge für deine Geräte und Freunde – geführt eingerichtet (Name, Gerät, QR-Code oder Datei mit passender
Anleitung), je Zugang „nur zu Hause“, „alles über zu Hause“ oder nur bestimmte Dienste, mit Ablaufdatum und Sperre.
Läuft wartungsfrei: hält Adresse und Router-Freigabe aktuell, sperrt abgelaufene Zugänge, prüft Verbindungen und Updates
und meldet Probleme gebündelt. Dazu Tailscale (mit Headscale), ZeroTier und NetBird im Blick.

[English](README.md) · Eine offizielle [Hostwerk](https://github.com/Passimoritz/hostwerk-public) Erweiterung (SDK 2.7, native Erweiterung)

## Was sie kann

- **Zustand oben:** läuft oder aus, Adresse von außen, Port im Router, WireGuard-Version, was von selbst läuft – und
  Befunde mit einem Knopf, der sie behebt (Starten, Freigeben, Einstellungen …)
- **Neuer Zugang in vier Schritten:** Wer → welches Gerät (Android, iPhone/iPad, Windows, Mac, Linux) → was darf er und
  wie lange → QR-Code oder Datei mit den Schritten für genau dieses Gerät
- **Zugänge im Überblick:** wer, Gerät, Reichweite, zuletzt verbunden, empfangene/gesendete Daten, Ende, an/aus,
  sperren, neue Schlüssel
- **Reichweite je Zugang:** *Nur zu Hause* (dieser PC, unter Linux auch das Heimnetz), *Alles über zu Hause* (Linux:
  Weiterleitung und NAT, DNS fürs Gerät gesetzt) oder *Nur bestimmte Dienste* (Ports deiner Hostwerk-Dienste – Linux per
  iptables, Windows per Firewall-Regeln unter derselben Administrator-Abfrage)
- WireGuard-Schlüssel entstehen in Hostwerk (X25519 plus PresharedKey) – ohne Kommandozeile; Mitglieder aus
  „Team & Rollen“ bekommen ihren eigenen Zugang
- **Andere Wege:** Tailscale mit Geräten, Exit-Node und Subnetz-Router (Befehle zum Kopieren), Headscale als eigener
  Server, ZeroTier und NetBird – erkannt und nur lesend gezeigt, mit ehrlichem Vergleich

## Wartungsfrei

Alle 15 Minuten (und bei *Jetzt alles prüfen*) erledigt Hostwerk von selbst, was sonst dich bräuchte:

| Was | Wie |
|---|---|
| Zugänge mit Ende | nach Ablauf gesperrt – und aus dem laufenden Tunnel genommen, wenn Hostwerk die Rechte hat (`wg set`, z. B. als Systemdienst); sonst „Neustart nötig“ |
| Adresse von außen | *DynDNS des Routers*: folgt dem Namen aus „Router & Portfreigaben“. *Eigene Domain*: hält den A/AAAA-Eintrag von z. B. `vpn.example.com` über die „DNS-Verwaltung“ auf deiner aktuellen IP. Feste IP als Adresse: ein IP-Wechsel wird gemeldet |
| Portfreigabe | der UDP-Port wird über „Router & Portfreigaben“ mit Besitzer `vpn` freigegeben, solange das VPN läuft, bei Portwechsel mitgezogen, repariert, wenn er fehlt, und beim Stoppen entfernt |
| Anschlussart | Carrier-NAT und DS-Lite werden erkannt – bei DS-Lite läuft das VPN über IPv6, ohne IPv4 und IPv6 empfiehlt die Seite Tailscale/ZeroTier/NetBird |
| Updates | Windows: täglicher Blick in die offizielle Liste (`download.wireguard.com/windows-client/latest.sig`, die auch WireGuards eigener Updater liest) – Hinweis mit `winget upgrade WireGuard.WireGuard`. Linux: Version wird gezeigt, Updates kommen mit den Paketen |
| Verbindungen | „zuletzt verbunden“ und Datenmenge werden gemerkt; einen Tag nach dem Start noch keine Verbindung oder ein Tunnel, der laufen sollte, aber aus ist, wird ein Befund |
| Schlüssel-Alter (optional) | Erinnerung nach 6, 12 oder 24 Monaten |

Neue Probleme kommen als **eine** Benachrichtigung (eigener Schalter unter Einstellungen → Benachrichtigungen, ab
Hostwerk 2.12), der Zustand steht in der Wächter-Liste (Livebetrieb → Wächter) und in der Selbstwartung. Reine Hinweise
lösen nie eine Benachrichtigung aus. Nie automatisch: Starten, Stoppen und neue Schlüssel – das braucht dich
(Administrator-Abfrage, neue Datei fürs Gerät).

## So geht’s

1. **Neuer Zugang** – fehlt die Adresse von außen, fragt der Assistent sie mit ab (*Vorschlagen* übernimmt DynDNS-Name
   oder öffentliche Adresse aus „Router & Portfreigaben“).
2. **Starten.** Hostwerk fragt vorher und erklärt die Administrator-Abfrage; erst dann richtet Windows den Tunneldienst
   ein (`wireguard.exe /installtunnelservice`) bzw. Linux führt `wg-quick up` über pkexec aus. *Stoppen* genauso.
3. QR-Code oder Datei weitergeben – die Seite zeigt die Schritte für die Geräteart.

## Sicherheit

- Private Schlüssel sind mit Hostwerks Geheimschlüssel versiegelt (`config/secret.key`, AES-256-GCM) und stehen in keiner
  Liste. Die Konfiguration eines Geräts (mit seinem privaten Schlüssel) kommt nur, wenn du sie öffnest.
- Die Datei für WireGuard (`data/vpn/hostwerk.conf`, nur für den Besitzer lesbar) entsteht direkt vor dem Start und wird
  nach dem Stoppen gelöscht. Live-Änderungen geben den PresharedKey über eine Temp-Datei weiter, nie in der Befehlszeile.
- *Sperren* nimmt den Zugang aus dem Tunnel; *Neue Schlüssel* macht die alte Konfiguration eines verlorenen Geräts wertlos.
- Zugänge „nur zu Hause“ können die Weiterleitung von „alles über zu Hause“-Zugängen nicht mitnutzen (FORWARD-Regel je
  Zugang) – ein Gerät, das seine AllowedIPs selbst erweitert, erreicht trotzdem nicht mehr als erlaubt.

## Für andere Erweiterungen: der Dienst `vpn`

`await host.use('vpn')` (oder `host.ctx.vpn`): `status()`, `peers()`, `addPeer({ person, device, member, platform, reach,
services, expires })`, `removePeer(id)`, `config(id)` → `{ file, text, qr, platform }`. Starten und Stoppen bleiben auf
dieser Seite, weil sie die Bestätigung des Nutzers brauchen.

## Grenzen

- Windows: Übers VPN ist nur dieser PC erreichbar; *Alles über zu Hause* braucht Linux.
- *Nur bestimmte Dienste* braucht unter Windows Hostwerk 2.12 oder neuer (eine Administrator-Abfrage für Tunnel und Firewall).
- Neustart = Stoppen + Starten, deshalb wird zweimal nach Administratorrechten gefragt. Live-Änderungen ohne Neustart
  gehen nur, wenn Hostwerk `wg set` ausführen darf (z. B. als Systemdienst oder unter Linux mit den Rechten dafür).
- Handschläge („zuletzt verbunden“) brauchen `wg show` – ohne Administratorrechte antwortet Windows nicht; dann zeigt sie
  die WireGuard-App.
- ZeroTier gibt seinen Zustand oft nur mit Administratorrechten heraus – dann steht das dort.
- Hostwerk legt bei Tailscale, ZeroTier und NetBird keine Konten an und ändert dort nichts.

## Installieren

In Hostwerk: **Erweiterungen → Entdecken** und „Installieren“ klicken.

Native Erweiterungen laufen als Teil von Hostwerk (eigener Server- und Oberflächen-Teil). Deshalb installiert Hostwerk sie nur aus dem offiziellen Katalog (mit Prüfsumme) oder im Entwickler-Modus.

## Daten

`data/vpn/state.json` – Einstellungen, Zugänge, Wartungsstand (zuletzt verbunden, Freigabe, Name, Befunde); private Schlüssel mit Hostwerks Geheimschlüssel (`config/secret.key`) versiegelt. `data/vpn/hostwerk.conf` gibt es nur beim Starten bzw. solange der Tunnel läuft. Entfernen der Erweiterung löscht nichts – vorher den Tunnel stoppen.

## Entwickeln

```bash
node --test tests/*.test.js          # Tests (System, Router, DNS und Abrufe sind Nachbildungen – nichts wird verändert)
node build-native.js .               # Oberfläche bauen (sdk/build-native.js aus hostwerk-public)
node check.js . --strict             # dieselbe Prüfung wie der Katalog (sdk/check.js)
```

Oberfläche in `ui/src`, Server-Teil in `server/` (`maint.js` = Wartungsregeln, `wgconf.js` = Dateien und
Firewall-Regeln, `system.js` = Programme). Texte im Code sind Englisch, Deutsch steht in `locales/de.json`.

## Lizenz

MIT
