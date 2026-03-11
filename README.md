# DMARC Report Processor

Python-Script, das DMARC-Reports aus einem IMAP-Postfach liest und in einer SQLite-Datenbank speichert.

## Anforderungen

- Verbinde mit IMAP-Server (Credentials aus `.env` / `.env.example`)
- IMAP-Ordner konfigurierbar über `IMAP_FOLDER`, Default: `INBOX`
- Finde Mails, die DMARC-Reports enthalten, und ermittle deren `Message-ID`
- Ist die `Message-ID` noch nicht in der SQLite-DB → extrahiere und parse den DMARC-Report in die DB
- Alle Felder des Reports speichern (Metadaten, Policy, Records, DKIM- und SPF-Auth-Ergebnisse)
- War die Mail vor der Verarbeitung ungelesen → danach als gelesen markieren (`\Seen`)
- Laufmodus: Cronjob (einmaliger Lauf, kein Daemon)

## Technische Details

- **Sprache:** Python 3 mit `.venv`
- **IMAP:** `imaplib` (TLS, Port 993), PEEK-Fetch (kein automatisches `\Seen`)
- **XML-Parser:** `defusedxml` (sicher gegen XML-Bomb / Entity-Expansion)
- **Datenbank:** SQLite3 mit 5 Tabellen

### Datenbankschema

- `processed_messages` – Deduplication via `Message-ID`
- `reports` – Metadaten & veröffentlichte Policy (`org_name`, `domain`, `adkim`, `aspf`, `p`, `sp`, `pct`, `fo`, …)
- `report_records` – Einzelne Einträge (`source_ip`, `count`, `disposition`, DKIM/SPF-Evaluierung, `reason`, `envelope_from`, `header_from`)
- `auth_dkim_results` – DKIM-Auth-Ergebnisse pro Record (beliebig viele)
- `auth_spf_results` – SPF-Auth-Ergebnisse pro Record (beliebig viele)

## Dateien

| Datei | Beschreibung |
|---|---|
| `dmarc_processor.py` | Hauptscript |
| `.env.example` | Konfigurationsvorlage |
| `requirements.txt` | Abhängigkeiten (`python-dotenv`, `defusedxml`) |
| `setup.sh` | Erstellt `.venv` und installiert Abhängigkeiten |

## Quickstart

```bash
cp .env.example .env
# .env anpassen (IMAP_HOST, IMAP_USER, IMAP_PASSWORD, …)
bash setup.sh
source .venv/bin/activate
python dmarc_processor.py
```

## Cronjob (täglich 6 Uhr)

```cron
0 6 * * * /path/to/dmarc-report-processor/.venv/bin/python /path/to/dmarc-report-processor/dmarc_processor.py
```
