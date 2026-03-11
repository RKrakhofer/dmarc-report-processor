#!/usr/bin/env python3
"""DMARC Report Processor – liest DMARC-Reports aus IMAP und speichert sie in SQLite."""

import gzip
import imaplib
import io
import logging
import os
import sqlite3
import zipfile
from pathlib import Path

import defusedxml.ElementTree as ET
from dotenv import load_dotenv
from email import policy as email_policy
from email.parser import BytesParser

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)
log = logging.getLogger(__name__)

load_dotenv()

IMAP_HOST     = os.environ['IMAP_HOST']
IMAP_PORT     = int(os.getenv('IMAP_PORT', '993'))
IMAP_USER     = os.environ['IMAP_USER']
IMAP_PASSWORD = os.environ['IMAP_PASSWORD']
IMAP_FOLDER   = os.getenv('IMAP_FOLDER', 'INBOX')
DB_PATH       = Path(os.getenv('DB_PATH', 'dmarc_reports.db'))

# Content-Types, die DMARC-Anhänge enthalten können
DMARC_CONTENT_TYPES = {
    'application/zip',
    'application/x-zip-compressed',
    'application/x-zip',
    'application/gzip',
    'application/x-gzip',
    'application/octet-stream',
    'text/xml',
    'application/xml',
}

DMARC_EXTENSIONS = {'.xml', '.zip', '.gz'}


# ---------------------------------------------------------------------------
# Datenbank
# ---------------------------------------------------------------------------

def init_db(conn: sqlite3.Connection) -> None:
    """Legt alle Tabellen an (idempotent)."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS processed_messages (
            message_id   TEXT PRIMARY KEY,
            processed_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS reports (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id    TEXT NOT NULL REFERENCES processed_messages(message_id),
            org_name      TEXT,
            org_email     TEXT,
            extra_contact TEXT,
            report_id     TEXT,
            date_begin    INTEGER,
            date_end      INTEGER,
            domain        TEXT,
            adkim         TEXT,
            aspf          TEXT,
            policy_p      TEXT,
            policy_sp     TEXT,
            policy_pct    INTEGER,
            policy_fo     TEXT
        );

        CREATE TABLE IF NOT EXISTS report_records (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            report_db_id   INTEGER NOT NULL REFERENCES reports(id),
            source_ip      TEXT,
            count          INTEGER,
            disposition    TEXT,
            dkim_eval      TEXT,
            spf_eval       TEXT,
            reason_type    TEXT,
            reason_comment TEXT,
            envelope_to    TEXT,
            header_from    TEXT,
            envelope_from  TEXT
        );

        CREATE TABLE IF NOT EXISTS auth_dkim_results (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id    INTEGER NOT NULL REFERENCES report_records(id),
            domain       TEXT,
            selector     TEXT,
            result       TEXT,
            human_result TEXT
        );

        CREATE TABLE IF NOT EXISTS auth_spf_results (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id INTEGER NOT NULL REFERENCES report_records(id),
            domain    TEXT,
            scope     TEXT,
            result    TEXT
        );
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# XML-Hilfsfunktionen
# ---------------------------------------------------------------------------

def _text(element, path: str, default: str | None = None) -> str | None:
    """Gibt den Textinhalt eines XML-Elements zurück."""
    if element is None:
        return default
    node = element.find(path)
    return node.text.strip() if node is not None and node.text else default


def _int(element, path: str, default: int | None = None) -> int | None:
    """Gibt den Integer-Wert eines XML-Elements zurück."""
    val = _text(element, path)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# DMARC-XML-Parser
# ---------------------------------------------------------------------------

def parse_dmarc_xml(xml_bytes: bytes, message_id: str, conn: sqlite3.Connection) -> int:
    """
    Parst einen DMARC-Report (XML-Bytes) und schreibt alle Felder in die DB.
    Der Aufrufer ist für das Commit/Rollback verantwortlich.
    Gibt die Anzahl der eingefügten Records zurück.
    """
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        log.warning("XML-Parse-Fehler: %s", exc)
        return 0

    if root.tag != 'feedback':
        log.debug("Kein DMARC-Feedback (Root-Tag: '%s')", root.tag)
        return 0

    meta = root.find('report_metadata')
    pol  = root.find('policy_published')

    cur = conn.cursor()
    cur.execute("""
        INSERT INTO reports (
            message_id, org_name, org_email, extra_contact, report_id,
            date_begin, date_end,
            domain, adkim, aspf, policy_p, policy_sp, policy_pct, policy_fo
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        message_id,
        _text(meta, 'org_name'),
        _text(meta, 'email'),
        _text(meta, 'extra_contact'),
        _text(meta, 'report_id'),
        _int(meta,  'date_range/begin'),
        _int(meta,  'date_range/end'),
        _text(pol,  'domain'),
        _text(pol,  'adkim'),
        _text(pol,  'aspf'),
        _text(pol,  'p'),
        _text(pol,  'sp'),
        _int(pol,   'pct'),
        _text(pol,  'fo'),
    ))
    report_db_id = cur.lastrowid

    record_count = 0
    for record in root.findall('record'):
        row         = record.find('row')
        identifiers = record.find('identifiers')
        auth        = record.find('auth_results')
        pol_eval    = row.find('policy_evaluated') if row is not None else None
        reason      = pol_eval.find('reason')      if pol_eval is not None else None

        cur.execute("""
            INSERT INTO report_records (
                report_db_id, source_ip, count,
                disposition, dkim_eval, spf_eval,
                reason_type, reason_comment,
                envelope_to, header_from, envelope_from
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report_db_id,
            _text(row,         'source_ip'),
            _int(row,          'count'),
            _text(pol_eval,    'disposition'),
            _text(pol_eval,    'dkim'),
            _text(pol_eval,    'spf'),
            _text(reason,      'type'),
            _text(reason,      'comment'),
            _text(identifiers, 'envelope_to'),
            _text(identifiers, 'header_from'),
            _text(identifiers, 'envelope_from'),
        ))
        record_id = cur.lastrowid

        if auth is not None:
            for dkim_el in auth.findall('dkim'):
                cur.execute("""
                    INSERT INTO auth_dkim_results (record_id, domain, selector, result, human_result)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    record_id,
                    _text(dkim_el, 'domain'),
                    _text(dkim_el, 'selector'),
                    _text(dkim_el, 'result'),
                    _text(dkim_el, 'human_result'),
                ))
            for spf_el in auth.findall('spf'):
                cur.execute("""
                    INSERT INTO auth_spf_results (record_id, domain, scope, result)
                    VALUES (?, ?, ?, ?)
                """, (
                    record_id,
                    _text(spf_el, 'domain'),
                    _text(spf_el, 'scope'),
                    _text(spf_el, 'result'),
                ))

        record_count += 1

    log.debug(
        "Report von '%s' (ID: %s): %d Records",
        _text(meta, 'org_name') or '?',
        _text(meta, 'report_id') or '?',
        record_count,
    )
    return record_count


# ---------------------------------------------------------------------------
# Anhang-Extraktion
# ---------------------------------------------------------------------------

def try_extract_xml(payload: bytes, filename: str, content_type: str) -> bytes | None:
    """
    Versucht XML-Bytes aus einem Mail-Anhang zu extrahieren.
    Unterstützt: ZIP, GZIP, direktes XML, application/octet-stream (auto-detect).
    """
    fn = filename.lower()

    # ZIP
    if content_type in ('application/zip', 'application/x-zip-compressed', 'application/x-zip') \
            or fn.endswith('.zip'):
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                for name in zf.namelist():
                    if name.lower().endswith('.xml'):
                        return zf.read(name)
        except zipfile.BadZipFile:
            log.debug("Kein gültiges ZIP in Anhang '%s'", filename)
        return None

    # GZIP
    if content_type in ('application/gzip', 'application/x-gzip') or fn.endswith('.gz'):
        try:
            return gzip.decompress(payload)
        except OSError:
            log.debug("Kein gültiges GZIP in Anhang '%s'", filename)
        return None

    # application/octet-stream: erst ZIP, dann GZIP versuchen
    if content_type == 'application/octet-stream':
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                for name in zf.namelist():
                    if name.lower().endswith('.xml'):
                        return zf.read(name)
        except zipfile.BadZipFile:
            pass
        try:
            return gzip.decompress(payload)
        except OSError:
            pass
        return None

    # Direkt XML
    if content_type in ('text/xml', 'application/xml') or fn.endswith('.xml'):
        return payload

    return None


def is_likely_dmarc_attachment(content_type: str, filename: str) -> bool:
    """Heuristik: Hat der Anhang einen DMARC-typischen Content-Type und Dateinamen?"""
    fn = filename.lower()
    return (
        content_type in DMARC_CONTENT_TYPES
        and any(fn.endswith(ext) for ext in DMARC_EXTENSIONS)
    ) or content_type in ('text/xml', 'application/xml')


def process_message(msg, message_id: str, conn: sqlite3.Connection) -> int:
    """Verarbeitet alle Anhänge einer Mail. Gibt Gesamtzahl eingelesener Records zurück."""
    total = 0
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        ct = part.get_content_type().lower()
        fn = part.get_filename() or ''
        if not is_likely_dmarc_attachment(ct, fn):
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        xml_bytes = try_extract_xml(payload, fn, ct)
        if xml_bytes:
            total += parse_dmarc_xml(xml_bytes, message_id, conn)
    return total


# ---------------------------------------------------------------------------
# IMAP-Verarbeitung
# ---------------------------------------------------------------------------

def process_mailbox(conn: sqlite3.Connection) -> None:
    log.info(
        "Verbinde mit %s:%d (Ordner: %s, User: %s)",
        IMAP_HOST, IMAP_PORT, IMAP_FOLDER, IMAP_USER,
    )
    parser = BytesParser(policy=email_policy.default)

    with imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT) as imap:
        imap.login(IMAP_USER, IMAP_PASSWORD)

        typ, data = imap.select(IMAP_FOLDER, readonly=False)
        if typ != 'OK':
            raise RuntimeError(f"IMAP SELECT fehlgeschlagen: {data}")

        typ, data = imap.search(None, 'ALL')
        if typ != 'OK':
            raise RuntimeError(f"IMAP SEARCH fehlgeschlagen: {data}")

        mail_ids = data[0].split()
        log.info("%d Mails im Ordner '%s'", len(mail_ids), IMAP_FOLDER)

        new_count  = 0
        skip_count = 0

        for mail_id in mail_ids:
            # Nur Message-ID aus Header laden (PEEK → kein \Seen-Setzen)
            typ, header_data = imap.fetch(mail_id, '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])')
            if typ != 'OK' or not header_data or header_data[0] is None:
                continue

            raw_header = header_data[0][1]
            header_msg = parser.parsebytes(raw_header)
            message_id = header_msg.get('message-id', '').strip()

            if not message_id:
                log.debug("Mail %s ohne Message-ID – übersprungen", mail_id.decode())
                continue

            # Bereits in der DB?
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM processed_messages WHERE message_id = ?", (message_id,))
            if cur.fetchone():
                skip_count += 1
                continue

            # War die Mail ungelesen? (vor dem Abrufen prüfen)
            typ, flags_data = imap.fetch(mail_id, '(FLAGS)')
            was_unread = (
                typ == 'OK'
                and bool(flags_data)
                and flags_data[0] is not None
                and b'\\Seen' not in flags_data[0]
            )

            # Vollständige Mail laden (PEEK → kein automatisches \Seen-Setzen)
            typ, full_data = imap.fetch(mail_id, '(BODY.PEEK[])')
            if typ != 'OK' or not full_data or full_data[0] is None:
                log.warning("Mail %s konnte nicht geladen werden", mail_id.decode())
                continue

            raw_mail = full_data[0][1]
            msg = parser.parsebytes(raw_mail)

            # Transaktion: processed_messages + alle Report-Daten atomar committen
            try:
                conn.execute(
                    "INSERT INTO processed_messages (message_id) VALUES (?)",
                    (message_id,),
                )
                record_count = process_message(msg, message_id, conn)

                if record_count > 0:
                    conn.commit()
                    new_count += 1
                    if was_unread:
                        imap.store(mail_id, '+FLAGS', '\\Seen')
                        log.debug("Als gelesen markiert: %s", message_id)
                    log.info("Verarbeitet: %s – %d Records eingefügt", message_id, record_count)
                else:
                    conn.rollback()
                    log.debug("Keine DMARC-Daten in Mail %s", message_id)

            except sqlite3.Error as exc:
                conn.rollback()
                log.error("Datenbankfehler bei %s: %s", message_id, exc)

        log.info(
            "Fertig: %d neue Reports verarbeitet, %d bereits bekannte übersprungen.",
            new_count, skip_count,
        )


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        init_db(conn)
        process_mailbox(conn)
    except KeyboardInterrupt:
        log.info("Abgebrochen.")
    except Exception:
        log.exception("Unbehandelter Fehler")
        raise
    finally:
        conn.close()


if __name__ == '__main__':
    main()
