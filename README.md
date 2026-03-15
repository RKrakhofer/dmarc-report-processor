# DMARC Report Processor

Python-Scripts, die DMARC-Reports aus einem IMAP- oder Exchange Online-Postfach lesen, in einer SQLite-Datenbank speichern und auswerten.

## Anforderungen

- Zwei Mail-Backends wählbar: `--imap` (klassischer IMAP-Server) oder `--xchg` (Exchange Online via Microsoft Graph API)
- Ordner konfigurierbar, kommagetrennte Liste, Standard `INBOX` / `Inbox`
- Finde Mails mit DMARC-Reports und ermittle deren `Message-ID` / `internetMessageId`
- Ist die `Message-ID` noch nicht in der SQLite-DB → extrahiere und parse den DMARC-Report in die DB
- Alle Felder des Reports speichern (Metadaten, Policy, Records, DKIM- und SPF-Auth-Ergebnisse)
- Erfolgreich verarbeitete Mails → in den Papierkorb verschieben
- Bereits bekannte Mails (doppelter Import) → ebenfalls in den Papierkorb verschieben
- Laufmodus: Cronjob (einmaliger Lauf, kein Daemon)
- Inkrementelles Scanning: IMAP via UIDs + UIDVALIDITY, Exchange via delta-Link

## Technische Details

- **Sprache:** Python 3 mit `.venv`
- **IMAP:** `imaplib` (TLS, Port 993), UID-basiert, PEEK-Fetch (kein automatisches `\Seen`)
- **Exchange Online:** `msal` (Client Credentials Flow) + `requests` → Microsoft Graph API; delta query für inkrementelles Scanning
- **XML-Parser:** `defusedxml` (sicher gegen XML-Bomb / Entity-Expansion)
- **Datenbank:** SQLite3 mit 6 Tabellen

### Datenbankschema

- `processed_messages` – Deduplication via `Message-ID`
- `reports` – Metadaten & veröffentlichte Policy (`org_name`, `domain`, `adkim`, `aspf`, `p`, `sp`, `pct`, `fo`, …)
- `report_records` – Einzelne Einträge (`source_ip`, `count`, `disposition`, DKIM/SPF-Evaluierung, `reason`, `envelope_to`, `envelope_from`, `header_from`)
- `auth_dkim_results` – DKIM-Auth-Ergebnisse pro Record (beliebig viele)
- `auth_spf_results` – SPF-Auth-Ergebnisse pro Record (beliebig viele)
- `folder_state` – Speichert `last_uid` + `UIDVALIDITY` (IMAP) bzw. `delta_link` (Exchange) pro Ordner

## Dateien

| Datei | Beschreibung |
|---|---|
| `dmarc_processor.py` | Processor: liest DMARC-Reports via IMAP oder Exchange Online |
| `dmarc_report.py` | Auswertungs-Report mit Bewertung |
| `.env.example` | Konfigurationsvorlage (IMAP + Exchange) |
| `requirements.txt` | Abhängigkeiten (`python-dotenv`, `defusedxml`, `msal`, `requests`) |
| `setup.sh` | Erstellt `.venv` und installiert Abhängigkeiten |

## Konfiguration (`.env`)

### IMAP (`--imap`)

```ini
IMAP_HOST=mail.domain.com
IMAP_PORT=993
IMAP_USER=dmarc@domain.com
IMAP_PASSWORD=geheimes-passwort

# Kommagetrennte Ordnerliste (Standard: INBOX)
IMAP_FOLDER=INBOX

# Papierkorb-Ordner (Standard: Trash)
TRASH_FOLDER=Trash

# Pfad zur SQLite-DB (Standard: dmarc_reports.db)
DB_PATH=dmarc_reports.db

# Eigene Domain für Spoofing-Erkennung im Report
MY_DOMAIN=domain.com
```

### Exchange Online (`--xchg`)

Voraussetzung: Azure AD App Registration mit **App-Only**-Berechtigung `Mail.ReadWrite`.

```ini
XCHG_TENANT_ID=00000000-0000-0000-0000-000000000000
XCHG_CLIENT_ID=00000000-0000-0000-0000-000000000000
XCHG_CLIENT_SECRET=dein-client-secret

# UPN oder E-Mail des Postfachs
XCHG_USER=dmarc@domain.com

# Kommagetrennte Ordnerliste (Standard: Inbox)
# Well-known: Inbox, Sent, Drafts, Deleted, Junk
XCHG_FOLDER=Inbox

# Papierkorb-Ordner (Standard: deleteditems)
XCHG_TRASH_FOLDER=deleteditems

DB_PATH=dmarc_reports.db
MY_DOMAIN=domain.com
```

## Quickstart

```bash
cp .env.example .env
# .env anpassen
bash setup.sh
source .venv/bin/activate

# IMAP
python dmarc_processor.py --imap

# Exchange Online
python dmarc_processor.py --xchg

# Auswertung
python dmarc_report.py
```

## dmarc_processor.py – Optionen

```
--imap         E-Mails von einem IMAP-Server lesen
--xchg         E-Mails von Exchange Online lesen (Microsoft Graph API)
-q, --quiet    Nur Warnungen/Fehler ausgeben (für Cronjob)
--rescan       Alle Ordner neu scannen (setzt Zustand zurück; Duplikate werden via Message-ID verhindert)
```

`--imap` und `--xchg` schließen sich gegenseitig aus; eine der beiden Optionen ist Pflicht.

## dmarc_report.py – Optionen

```
--envelope-to DOMAIN      Alle Details für Einträge mit dieser envelope_to-Domain
-l, --list GLOB           Listet envelope_to-Domains mit Mailanzahl; Wildcards * und ? erlaubt
--arc                     Zeigt Records, bei denen ein Provider die DMARC-Policy überschrieben hat
--timeline <N>[dwmy]      Reputation-Zeitverlauf (d=Tage, w=Wochen, m=Monate, y=Jahre)
                          Beispiele: 30d, 4w, 12m, 2y
```

Ohne Option: vollständiger Report mit 7 Sektionen:
1. Gesamtübersicht (Mails pro Domain/Org)
2. Probleme (DKIM oder SPF fail)
3. Blockierte Mails (reject/quarantine)
4. Verdächtig (DKIM + SPF beide fail)
5. Eigene Domain im From mit Auth-Fehler
6. Zeitraum der Reports
7. Bewertung (inkl. DNS-Check auf Spoofing-Subdomains)

### Timeline-Ausgabe

Visualisiert die DKIM-Pass-Rate (= Domain-Reputation) als ASCII-Balkendiagramm, aggregiert nach Zeiteinheit:

```
════ REPUTATION-TIMELINE – example.com – letzte 30 Tage ════
  Score = DKIM-Pass-Rate  |  ░ = 0%   █ = 100%  |  ⚠ Spoofing  ✗ Blockiert

  Zeitraum        Total  DKIM✓  SPF✓  Spoof   Blk   Score  Verlauf
  2026-02-12        234    234    220      0     0  100.0%  ██████████████████████████████
  2026-02-20        189    185    180      2     0   97.9%  █████████████████████████████░ ⚠

  Trend: ↑  Verbessert  (+0.9%)
```

## Cronjob (täglich 6 Uhr)

```cron
# IMAP
0 6 * * * /path/to/dmarc-report-processor/.venv/bin/python /path/to/dmarc-report-processor/dmarc_processor.py --imap -q

# Exchange Online
0 6 * * * /path/to/dmarc-report-processor/.venv/bin/python /path/to/dmarc-report-processor/dmarc_processor.py --xchg -q
```
