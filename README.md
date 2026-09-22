# VPN-Manager für OPNsense

Kleines Web-Tool (Docker), mit dem der Admin beim Kunden OpenVPN-Zugänge für Mitarbeiter auf einer
OPNsense (26.x) verwaltet: Tunnel anlegen, Benutzer anlegen, Download-Paket mit Anleitung erzeugen,
Status der verbundenen Benutzer ansehen.

**Anmeldung der Mitarbeiter:** Zertifikat (im Profil) + Benutzername/Passwort + TOTP-Code (Authenticator-App).
Den Code fragt OpenVPN Connect in einem eigenen Feld ab ("static-challenge").

## Funktionen

- Login für Administratoren mit Pflicht-2FA (TOTP), Sperre nach 5 Fehlversuchen
- OPNsense-Verbindung im Tool einrichten, inkl. **Verbindungstest**, der jede benötigte API-Berechtigung einzeln prüft
- Tunnel (OpenVPN-Instanzen) anlegen, ändern, neu starten, löschen
  - eigene CA pro Tunnel (der CA-Key bleibt im Tool), Server-Zertifikat, tls-crypt-Key
  - Split-Tunnel (nur freigegebene Netze) oder Full-Tunnel, jederzeit umstellbar
  - optional automatische Firewall-Regeln (WAN-Einwahl + Zugriff der VPN-Clients)
- Benutzer anlegen mit **einem Formular**: Passwort, TOTP-Schlüssel, Client-Zertifikat und OPNsense-Benutzer werden automatisch erzeugt
- Download-Paket (ZIP): `.ovpn`-Profil, PDF-Anleitung (Windows/macOS/Android/iOS), LIESMICH
- Zugangsdatenblatt (PDF mit Passwort + QR-Code), getrennt vom Paket, wird nach Übergabe aus dem Tool gelöscht
- Status: Dienst läuft/gestoppt, verbundene Benutzer mit IP, Traffic, Verbindungsdauer, Verbindung trennen
- Benutzer sperren/entsperren, neues Passwort, neuer 2FA-Schlüssel, Profil neu ausstellen, löschen
- Protokoll aller Aktionen

## Installation beim Kunden

Es wird **keine `.env`-Datei benötigt**. Alle Variablen sind optional und haben Standardwerte:

| Variable | Standard | Bedeutung |
|---|---|---|
| `HOST_PORT` | `8443` | Port auf dem Docker-Host |
| `SECRET_KEY` | *(automatisch)* | Schlüssel für gespeicherte Geheimnisse. Fehlt er, wird er beim ersten Start in `/data/.secret_key` erzeugt |
| `APP_TITLE` | `VPN-Manager` | Name in der Oberfläche |
| `TZ` | `Europe/Berlin` | Zeitzone |
| `TLS_ENABLED` | `true` | HTTPS im Container (selbstsigniert, in `/data/tls`) |

**Dockhand / Portainer:** Das Repo als Git-Stack hinzufügen und deployen. Variablen bei Bedarf in den
Stack-Variablen setzen.

**Kommandozeile:**

```bash
git clone <repo> vpnmanager && cd vpnmanager
cp .env.example .env    # optional, um Werte anzupassen
docker compose up -d --build
```

Danach `https://<docker-host>:8443` öffnen. Der erste Aufruf führt zur Ersteinrichtung (Admin + 2FA).

Alle Daten liegen im Docker-Volume `vpnmanager-data` (Datenbank, Schlüssel, TLS-Zertifikat).
Ein eigenes TLS-Zertifikat kann als `/data/tls/cert.pem` und `/data/tls/key.pem` hinterlegt werden
(z. B. per `docker cp`). Läuft ein Reverse-Proxy davor, `TLS_ENABLED=false` setzen.

> **Wichtig:** Das Volume `vpnmanager-data` sichern (bzw. den gesetzten `SECRET_KEY`). Ohne den Schlüssel sind
> CA, Client-Zertifikate und das API-Secret nicht mehr lesbar. Ein einmal verwendeter `SECRET_KEY` darf
> nicht geändert werden.

## Vorbereitung auf der OPNsense (einmalig)

1. **API-Benutzer** unter *System → Zugang → Benutzer* anlegen, Rechte:
   - VPN: OpenVPN: Instances
   - Status: OpenVPN
   - System: Trust: Authorities, System: Trust: Certificates
   - System: Access: Users
   - Firewall: Rules (optional, für automatische Regeln)

   Anschließend einen API-Key erzeugen und Key und Secret im Tool unter *OPNsense* eintragen.
2. **Authentifizierungsserver** unter *System → Zugang → Server*: Typ *Local + Timebased One Time Password*
   (z. B. Name `VPN-TOTP`, Standardwerte). Diesen beim Anlegen eines Tunnels auswählen.
3. Die öffentliche Adresse (DNS-Name/IP) der OPNsense und die Portweiterleitung (falls die OPNsense hinter
   einem Router steht) müssen passen.
4. Full-Tunnel: Das ausgehende NAT muss auf *Automatisch* oder *Hybrid* stehen (Standard).

## Wie es auf der OPNsense aussieht

Alle Objekte tragen den Präfix `vpnmanager` in der Beschreibung:

| Objekt | Ort in der OPNsense |
|---|---|
| CA (nur Zertifikat, kein Key) | System → Trust → Authorities |
| Server-Zertifikat | System → Trust → Certificates |
| tls-crypt-Key | VPN → OpenVPN → Instances → Static Keys |
| OpenVPN-Instanz | VPN → OpenVPN → Instances |
| VPN-Benutzer (mit OTP-Seed) | System → Zugang → Benutzer |
| Firewall-Regeln (optional) | Firewall → Rules |

Wichtige Einstellungen der Instanz: `strictusercn` (Benutzername muss zum Zertifikat passen),
`auth-gen-token` (nach der Anmeldung kein neuer 2FA-Code bei Netzwechsel, solange die Sitzungsdauer
nicht abgelaufen ist), Zertifikats-Prüfung + `remote-cert-tls`.

Client-Zertifikate werden **nicht** auf der OPNsense gespeichert. Weil jeder Tunnel eine eigene CA hat,
funktioniert ein Profil nur mit seinem Tunnel. Wird ein Benutzer gesperrt oder gelöscht, ist sein
Profil wertlos, weil zusätzlich Passwort und TOTP geprüft werden.

## Entwicklung

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
SECRET_KEY=$(openssl rand -hex 32) DATA_DIR=./data TLS_ENABLED=false .venv/bin/uvicorn app.main:app --reload --port 8080
```

Aufbau:

| Datei | Inhalt |
|---|---|
| `app/main.py` | Routen, Login/2FA, CSRF |
| `app/services.py` | Abläufe (Tunnel/Benutzer anlegen, Status …) |
| `app/opnsense.py` | API-Client für OPNsense |
| `app/pki.py` | CA/Zertifikate, tls-crypt-Key |
| `app/ovpn.py` | `.ovpn`-Profil |
| `app/package.py` | ZIP, PDF-Anleitung, Zugangsdatenblatt |
| `app/db.py` | SQLite-Modelle |
