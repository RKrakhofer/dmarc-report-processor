# DMARC Report Processor

Python-Scripts, die DMARC-Reports aus einem IMAP-Postfach lesen, in einer SQLite-Datenbank speichern und auswerten.

## Anforderungen

- Verbinde mit IMAP-Server (Credentials aus `.env` / `.env.example`)
- IMAP-Ordner konfigurierbar über `IMAP_FOLDER` (kommagetrennte Liste), Default: `INBOX`
- Finde Mails, die DMARC-Reports enthalten, und ermittle deren `Message-ID`
- Ist die `Message-ID` noch nicht in der SQLite-DB → extrahiere und parse den DMARC-Report in die DB
- Alle Felder des Reports speichern (Metadaten, Policy, Records, DKIM- und SPF-Auth-Ergebnisse)
- War die Mail vor der Verarbeitung ungelesen → danach als gelesen markieren (`\Seen`)
- Laufmodus: Cronjob (einmaliger Lauf, kein Daemon)
- Inkrementelles Scanning via IMAP-UIDs – nur neue Mails werden geprüft (mit UIDVALIDITY-Sicherung)

## Technische Details

- **Sprache:** Python 3 mit `.venv`
- **IMAP:** `imaplib` (TLS, Port 993), UID-basiert, PEEK-Fetch (kein automatisches `\Seen`)
- **XML-Parser:** `defusedxml` (sicher gegen XML-Bomb / Entity-Expansion)
- **Datenbank:** SQLite3 mit 6 Tabellen

### Datenbankschema

- `processed_messages` – Deduplication via `Message-ID`
- `reports` – Metadaten & veröffentlichte Policy (`org_name`, `domain`, `adkim`, `aspf`, `p`, `sp`, `pct`, `fo`, …)
- `report_records` – Einzelne Einträge (`source_ip`, `count`, `disposition`, DKIM/SPF-Evaluierung, `reason`, `envelope_to`, `envelope_from`, `header_from`)
- `auth_dkim_results` – DKIM-Auth-Ergebnisse pro Record (beliebig viele)
- `auth_spf_results` – SPF-Auth-Ergebnisse pro Record (beliebig viele)
- `folder_state` – Speichert `last_uid` und `UIDVALIDITY` pro Ordner für inkrementelles Scanning

## Dateien

| Datei | Beschreibung |
|---|---|
| `dmarc_processor.py` | IMAP-Processor: liest und importiert DMARC-Reports |
| `dmarc_report.py` | Auswertungs-Report mit Bewertung |
| `.env.example` | Konfigurationsvorlage |
| `requirements.txt` | Abhängigkeiten (`python-dotenv`, `defusedxml`) |
| `setup.sh` | Erstellt `.venv` und installiert Abhängigkeiten |

## Konfiguration (`.env`)

```ini
IMAP_HOST=mail.domain.com
IMAP_PORT=993
IMAP_USER=dmarc@domain.com
IMAP_PASSWORD=geheimes-passwort

# Eigene Domain für Spoofing-Erkennung im Report
MY_DOMAIN=domain.com

# Kommagetrennte Ordnerliste (Standard: INBOX)
IMAP_FOLDER=INBOX,DMARC

# Pfad zur SQLite-DB (Standard: dmarc_reports.db)
DB_PATH=dmarc_reports.db
```

## Quickstart

```bash
cp .env.example .env
# .env anpassen
bash setup.sh
source .venv/bin/activate
python dmarc_processor.py   # Mails importieren
python dmarc_report.py      # Auswertung anzeigen
```

## dmarc_processor.py – Optionen

```
-q, --quiet    Nur Warnungen/Fehler ausgeben (für Cronjob)
--rescan       Alle Ordner neu scannen (setzt last_uid zurück, Duplikate werden via Message-ID verhindert)
```

## dmarc_report.py – Optionen

```
--envelope-to DOMAIN    Zeige alle Details für Einträge mit dieser envelope_to-Domain
```

Ohne Option: vollständiger Report mit 7 Sektionen:
1. Gesamtübersicht (Mails pro Domain/Org)
2. Probleme (DKIM oder SPF fail)
3. Blockierte Mails (reject/quarantine)
4. Verdächtig (DKIM + SPF beide fail)
5. Eigene Domain im From mit Auth-Fehler
6. Zeitraum der Reports
7. Bewertung (inkl. DNS-Check auf Spoofing-Subdomains)

## Cronjob (täglich 6 Uhr)

```cron
0 6 * * * /path/to/dmarc-report-processor/.venv/bin/python /path/to/dmarc-report-processor/dmarc_processor.py -q
```

