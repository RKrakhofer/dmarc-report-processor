#!/usr/bin/env python3
"""DMARC Report Processor – liest DMARC-Reports aus IMAP und speichert sie in SQLite."""

import argparse
import gzip
import imaplib
import io
import logging
import os
import sqlite3
import zipfile
from pathlib import Path

import re

import defusedxml.ElementTree as ET
from dotenv import load_dotenv
from email import policy as email_policy
from email.parser import BytesParser

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)
log = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='DMARC Report Processor')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Nur Warnungen und Fehler ausgeben (für Cronjob)')
    parser.add_argument('--rescan', action='store_true',
                        help='Alle Ordner neu scannen (setzt Zustand zurück)')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--imap', action='store_true',
                      help='E-Mails von einem IMAP-Server lesen')
    mode.add_argument('--xchg', action='store_true',
                      help='E-Mails von Exchange Online lesen (Microsoft Graph API)')
    return parser.parse_args()

load_dotenv()

# IMAP-Konfiguration
IMAP_HOST     = os.getenv('IMAP_HOST', '')
IMAP_PORT     = int(os.getenv('IMAP_PORT', '993'))
IMAP_USER     = os.getenv('IMAP_USER', '')
IMAP_PASSWORD = os.getenv('IMAP_PASSWORD', '')
IMAP_FOLDER   = [f.strip() for f in os.getenv('IMAP_FOLDER', 'INBOX').split(',') if f.strip()]
TRASH_FOLDER  = os.getenv('TRASH_FOLDER', 'Trash')
DB_PATH       = Path(os.getenv('DB_PATH', 'dmarc_reports.db'))

# Exchange Online-Konfiguration (Microsoft Graph API)
XCHG_TENANT_ID     = os.getenv('XCHG_TENANT_ID', '')
XCHG_CLIENT_ID     = os.getenv('XCHG_CLIENT_ID', '')
XCHG_CLIENT_SECRET = os.getenv('XCHG_CLIENT_SECRET', '')
XCHG_USER          = os.getenv('XCHG_USER', '')   # UPN oder E-Mail des Postfachs
XCHG_FOLDER        = [f.strip() for f in os.getenv('XCHG_FOLDER', 'Inbox').split(',') if f.strip()]
XCHG_TRASH_FOLDER  = os.getenv('XCHG_TRASH_FOLDER', 'deleteditems')

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

        CREATE TABLE IF NOT EXISTS folder_state (
            folder      TEXT PRIMARY KEY,
            uidvalidity INTEGER NOT NULL,
            last_uid    INTEGER NOT NULL DEFAULT 0,
            delta_link  TEXT
        );
    """)
    conn.commit()
    # Migration: delta_link für Exchange Online (existierende Datenbanken)
    try:
        conn.execute('ALTER TABLE folder_state ADD COLUMN delta_link TEXT')
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Spalte existiert bereits


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

def _strip_xml_namespaces(xml_bytes: bytes) -> bytes:
    """Entfernt XML-Namespace-Deklarationen und -Präfixe damit ElementTree ohne ns-Handling arbeitet."""
    # xmlns="..." und xmlns:prefix="..." entfernen
    xml_bytes = re.sub(rb'\s+xmlns(?::\w+)?="[^"]*"', b'', xml_bytes)
    # Namespace-Präfixe von Tags entfernen: <ns:tag> / </ns:tag>
    xml_bytes = re.sub(rb'<(/?)(\w+:)', rb'<\1', xml_bytes)
    return xml_bytes


def parse_dmarc_xml(xml_bytes: bytes, message_id: str, conn: sqlite3.Connection) -> int:
    """
    Parst einen DMARC-Report (XML-Bytes) und schreibt alle Felder in die DB.
    Der Aufrufer ist für das Commit/Rollback verantwortlich.
    Gibt die Anzahl der eingefügten Records zurück.
    """
    xml_bytes = _strip_xml_namespaces(xml_bytes)
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

def _move_to_trash(imap: imaplib.IMAP4_SSL, uid: bytes, trash_folder: str) -> bool:
    """Verschiebt eine Mail per UID in den Papierkorb. Gibt True bei Erfolg zurück."""
    # Versuche MOVE (RFC 6851) – atomar und effizient
    typ, _ = imap.uid('MOVE', uid, trash_folder)
    if typ == 'OK':
        return True
    # Fallback: COPY + als gelöscht markieren
    typ, _ = imap.uid('COPY', uid, trash_folder)
    if typ != 'OK':
        log.warning("COPY nach '%s' fehlgeschlagen für UID %s", trash_folder, uid.decode())
        return False
    imap.uid('STORE', uid, '+FLAGS', '\\Deleted')
    imap.expunge()
    return True


def _load_folder_state(conn: sqlite3.Connection, folder: str) -> tuple[int, int]:
    """Lädt (uidvalidity, last_uid) aus der DB. Gibt (0, 0) wenn noch kein Eintrag."""
    row = conn.execute(
        "SELECT uidvalidity, last_uid FROM folder_state WHERE folder = ?", (folder,)
    ).fetchone()
    return (row[0], row[1]) if row else (0, 0)


def _save_folder_state(conn: sqlite3.Connection, folder: str, uidvalidity: int, last_uid: int) -> None:
    conn.execute(
        "INSERT INTO folder_state (folder, uidvalidity, last_uid) VALUES (?, ?, ?)"
        " ON CONFLICT(folder) DO UPDATE SET uidvalidity = excluded.uidvalidity, last_uid = excluded.last_uid",
        (folder, uidvalidity, last_uid),
    )
    conn.commit()


def _process_folder(imap: imaplib.IMAP4_SSL, folder: str, parser: BytesParser, conn: sqlite3.Connection) -> tuple[int, int, int]:
    """Verarbeitet einen einzelnen IMAP-Ordner. Gibt (new_count, skip_count, trash_count) zurück."""
    typ, data = imap.select(folder, readonly=False)
    if typ != 'OK':
        log.warning("IMAP SELECT fehlgeschlagen für Ordner '%s': %s", folder, data)
        return 0, 0, 0

    # UIDVALIDITY per STATUS-Befehl holen (zuverlässig, kein Dummy-Search nötig)
    uidvalidity: int | None = None
    typ3, status_data = imap.status(folder, '(UIDVALIDITY)')
    if typ3 == 'OK' and status_data:
        raw = status_data[0]
        if isinstance(raw, bytes) and b'UIDVALIDITY' in raw:
            try:
                uidvalidity = int(raw.split(b'UIDVALIDITY')[1].strip().rstrip(b')'))
            except (ValueError, IndexError):
                pass

    if uidvalidity is None:
        log.warning("Konnte UIDVALIDITY für '%s' nicht ermitteln – Full-Scan", folder)
        uidvalidity = 0

    saved_uidvalidity, last_uid = _load_folder_state(conn, folder)

    if saved_uidvalidity != uidvalidity:
        if saved_uidvalidity != 0:
            log.warning(
                "UIDVALIDITY für '%s' hat sich geändert (%d → %d) – Full-Rescan",
                folder, saved_uidvalidity, uidvalidity,
            )
        last_uid = 0

    search_range = f'{last_uid + 1}:*'
    typ, data = imap.uid('SEARCH', 'UID', search_range)
    if typ != 'OK':
        log.warning("IMAP UID SEARCH fehlgeschlagen für Ordner '%s': %s", folder, data)
        return 0, 0, 0

    uid_list = [uid for uid in data[0].split() if int(uid) > last_uid]
    log.info("%d neue Mails (UID > %d) im Ordner '%s'", len(uid_list), last_uid, folder)

    if not uid_list:
        _save_folder_state(conn, folder, uidvalidity, last_uid)
        return 0, 0, 0

    mail_ids = uid_list  # ab hier UIDs statt Sequence Numbers

    seen_in_batch: set[str] = set()
    new_count   = 0
    skip_count  = 0
    trash_count = 0
    max_uid     = last_uid

    for uid in mail_ids:
        uid_int = int(uid)

        # Message-ID + FLAGS in einem PEEK-Fetch holen
        typ, fetch_data = imap.uid('FETCH', uid, '(FLAGS BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])')
        if typ != 'OK' or not fetch_data or fetch_data[0] is None:
            continue

        raw_header = fetch_data[0][1]
        header_msg = parser.parsebytes(raw_header)
        message_id = header_msg.get('message-id', '').strip()

        if not message_id:
            log.debug("UID %s ohne Message-ID – übersprungen", uid.decode())
            max_uid = max(max_uid, uid_int)
            continue

        # Message-ID als Sicherheitsnetz gegen UID-Kollisionen nach UIDVALIDITY-Reset
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM processed_messages WHERE message_id = ?", (message_id,))
        if cur.fetchone():
            # Bereits in DB bekannt → immer in Papierkorb schieben
            if _move_to_trash(imap, uid, TRASH_FOLDER):
                trash_count += 1
                log.info("Bereits bekannte Mail in Papierkorb verschoben: %s (UID %s)", message_id, uid.decode())
            else:
                skip_count += 1
            max_uid = max(max_uid, uid_int)
            continue

        was_unread = b'\\Seen' not in fetch_data[0][0]

        typ, full_data = imap.uid('FETCH', uid, '(BODY.PEEK[])')
        if typ != 'OK' or not full_data or full_data[0] is None:
            log.warning("UID %s konnte nicht geladen werden", uid.decode())
            continue

        raw_mail = full_data[0][1]
        msg = parser.parsebytes(raw_mail)

        try:
            conn.execute(
                "INSERT INTO processed_messages (message_id) VALUES (?)",
                (message_id,),
            )
            record_count = process_message(msg, message_id, conn)

            if record_count > 0:
                conn.commit()
                seen_in_batch.add(message_id)
                new_count += 1
                log.info("Verarbeitet: %s – %d Records eingefügt", message_id, record_count)
                if _move_to_trash(imap, uid, TRASH_FOLDER):
                    trash_count += 1
                    log.info("In Papierkorb verschoben: %s (UID %s)", message_id, uid.decode())
                else:
                    # Fallback: wenigstens als gelesen markieren
                    if was_unread:
                        imap.uid('STORE', uid, '+FLAGS', '\\Seen')
                        log.debug("Als gelesen markiert: %s", message_id)
            else:
                conn.rollback()
                log.debug("Keine DMARC-Daten in UID %s", uid.decode())

        except sqlite3.Error as exc:
            conn.rollback()
            log.error("Datenbankfehler bei %s: %s", message_id, exc)

        max_uid = max(max_uid, uid_int)

    _save_folder_state(conn, folder, uidvalidity, max_uid)
    return new_count, skip_count, trash_count


def process_mailbox(conn: sqlite3.Connection) -> None:
    missing = [name for name, val in [
        ('IMAP_HOST', IMAP_HOST), ('IMAP_USER', IMAP_USER), ('IMAP_PASSWORD', IMAP_PASSWORD),
    ] if not val]
    if missing:
        raise RuntimeError(f"Fehlende IMAP-Umgebungsvariablen: {', '.join(missing)}")
    log.info(
        "Verbinde mit %s:%d (Ordner: %s, User: %s)",
        IMAP_HOST, IMAP_PORT, ', '.join(IMAP_FOLDER), IMAP_USER,
    )
    parser = BytesParser(policy=email_policy.default)

    with imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT) as imap:
        imap.login(IMAP_USER, IMAP_PASSWORD)

        total_new   = 0
        total_skip  = 0
        total_trash = 0

        for folder in IMAP_FOLDER:
            new, skip, trash = _process_folder(imap, folder, parser, conn)
            total_new   += new
            total_skip  += skip
            total_trash += trash

        log.info(
            "Fertig: %d neue Reports verarbeitet, %d bereits bekannte in Papierkorb, %d Moves fehlgeschlagen.",
            total_new, total_trash, total_skip,
        )


# ---------------------------------------------------------------------------
# Exchange Online-Verarbeitung (Microsoft Graph API)
# ---------------------------------------------------------------------------

GRAPH_BASE = 'https://graph.microsoft.com/v1.0'


def _xchg_get_token() -> str:
    """Holt ein OAuth2 Bearer-Token via Client Credentials Flow (App-Only)."""
    try:
        import msal
    except ImportError:
        raise ImportError("'msal' nicht installiert. Bitte: pip install msal")
    app = msal.ConfidentialClientApplication(
        XCHG_CLIENT_ID,
        authority=f'https://login.microsoftonline.com/{XCHG_TENANT_ID}',
        client_credential=XCHG_CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(scopes=['https://graph.microsoft.com/.default'])
    if 'access_token' not in result:
        raise RuntimeError(f"Exchange-Token-Fehler: {result.get('error_description', result)}")
    return result['access_token']


def _xchg_resolve_folder(session, user: str, folder_name: str) -> str:
    """Löst einen Ordner-Namen in eine Folder-ID auf."""
    well_known = {
        'inbox': 'inbox', 'sent': 'sentitems', 'sentitems': 'sentitems',
        'drafts': 'drafts', 'deleted': 'deleteditems', 'deleteditems': 'deleteditems',
        'junk': 'junkemail', 'spam': 'junkemail',
    }
    key = folder_name.lower().replace(' ', '')
    if key in well_known:
        return well_known[key]
    url = (f"{GRAPH_BASE}/users/{user}/mailFolders"
           f"?$filter=displayName eq '{folder_name}'&$select=id")
    resp = session.get(url)
    resp.raise_for_status()
    items = resp.json().get('value', [])
    if not items:
        raise ValueError(f"Exchange-Ordner nicht gefunden: '{folder_name}'")
    return items[0]['id']


def _load_xchg_delta_link(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute(
        "SELECT delta_link FROM folder_state WHERE folder = ?", (key,)
    ).fetchone()
    return row[0] if row else None


def _save_xchg_delta_link(conn: sqlite3.Connection, key: str, delta_link: str) -> None:
    conn.execute(
        "INSERT INTO folder_state (folder, uidvalidity, last_uid, delta_link) VALUES (?, 0, 0, ?)"
        " ON CONFLICT(folder) DO UPDATE SET delta_link = excluded.delta_link",
        (key, delta_link),
    )
    conn.commit()


def _xchg_process_folder(
    session, folder_name: str, parser: BytesParser, conn: sqlite3.Connection,
) -> tuple[int, int, int]:
    """Verarbeitet einen Exchange-Online-Ordner. Gibt (new_count, skip_count, trash_count) zurück."""
    user      = XCHG_USER
    folder_id = _xchg_resolve_folder(session, user, folder_name)
    state_key = f'xchg:{folder_name}'
    delta_url = _load_xchg_delta_link(conn, state_key)

    if delta_url is None:
        delta_url = (
            f'{GRAPH_BASE}/users/{user}/mailFolders/{folder_id}/messages/delta'
            '?$select=id,internetMessageId,isRead&$top=50'
        )

    new_count   = 0
    skip_count  = 0
    trash_count = 0
    next_delta  = None

    while delta_url:
        resp = session.get(delta_url)
        resp.raise_for_status()
        data      = resp.json()
        messages  = data.get('value', [])
        next_delta = data.get('@odata.deltaLink')
        delta_url  = data.get('@odata.nextLink')

        log.info("%d Mails abgerufen aus Exchange-Ordner '%s'", len(messages), folder_name)

        for msg_meta in messages:
            msg_id_graph    = msg_meta['id']
            internet_msg_id = msg_meta.get('internetMessageId', '').strip()
            if not internet_msg_id:
                log.debug("Exchange-Mail ohne internetMessageId – übersprungen")
                continue

            cur = conn.cursor()
            cur.execute("SELECT 1 FROM processed_messages WHERE message_id = ?", (internet_msg_id,))
            if cur.fetchone():
                try:
                    mv = session.post(
                        f'{GRAPH_BASE}/users/{user}/messages/{msg_id_graph}/move',
                        json={'destinationId': XCHG_TRASH_FOLDER},
                    )
                    mv.raise_for_status()
                    trash_count += 1
                    log.info("Bereits bekannte Mail in Papierkorb: %s", internet_msg_id)
                except Exception as exc:
                    log.warning("Papierkorb-Move fehlgeschlagen: %s", exc)
                    skip_count += 1
                continue

            # Rohe RFC-822-Nachricht laden
            try:
                mime_resp = session.get(
                    f'{GRAPH_BASE}/users/{user}/messages/{msg_id_graph}/$value',
                )
                mime_resp.raise_for_status()
                raw_mail = mime_resp.content
            except Exception as exc:
                log.warning("Konnte Exchange-Mail nicht laden (%s): %s", internet_msg_id, exc)
                continue

            msg = parser.parsebytes(raw_mail)
            try:
                conn.execute(
                    "INSERT INTO processed_messages (message_id) VALUES (?)",
                    (internet_msg_id,),
                )
                record_count = process_message(msg, internet_msg_id, conn)

                if record_count > 0:
                    conn.commit()
                    new_count += 1
                    log.info("Verarbeitet: %s – %d Records", internet_msg_id, record_count)
                    try:
                        mv = session.post(
                            f'{GRAPH_BASE}/users/{user}/messages/{msg_id_graph}/move',
                            json={'destinationId': XCHG_TRASH_FOLDER},
                        )
                        mv.raise_for_status()
                        trash_count += 1
                    except Exception as exc:
                        log.warning("Papierkorb-Move fehlgeschlagen für %s: %s", internet_msg_id, exc)
                else:
                    conn.rollback()
                    log.debug("Keine DMARC-Daten in Exchange-Mail %s", internet_msg_id)

            except sqlite3.Error as exc:
                conn.rollback()
                log.error("Datenbankfehler bei %s: %s", internet_msg_id, exc)

    if next_delta:
        _save_xchg_delta_link(conn, state_key, next_delta)

    return new_count, skip_count, trash_count


def process_mailbox_exchange(conn: sqlite3.Connection) -> None:
    """Liest DMARC-Reports aus einem Exchange Online-Postfach via Microsoft Graph API."""
    missing = [name for name, val in [
        ('XCHG_TENANT_ID', XCHG_TENANT_ID), ('XCHG_CLIENT_ID', XCHG_CLIENT_ID),
        ('XCHG_CLIENT_SECRET', XCHG_CLIENT_SECRET), ('XCHG_USER', XCHG_USER),
    ] if not val]
    if missing:
        raise RuntimeError(f"Fehlende Exchange-Umgebungsvariablen: {', '.join(missing)}")

    log.info("Exchange Online: Tenant=%s, User=%s, Ordner=%s",
             XCHG_TENANT_ID, XCHG_USER, ', '.join(XCHG_FOLDER))
    token = _xchg_get_token()

    try:
        import requests
    except ImportError:
        raise ImportError("'requests' nicht installiert. Bitte: pip install requests")

    session = requests.Session()
    session.headers.update({'Authorization': f'Bearer {token}'})

    parser = BytesParser(policy=email_policy.default)
    total_new   = 0
    total_skip  = 0
    total_trash = 0

    for folder_name in XCHG_FOLDER:
        new, skip, trash = _xchg_process_folder(session, folder_name, parser, conn)
        total_new   += new
        total_skip  += skip
        total_trash += trash

    log.info(
        "Fertig (Exchange): %d neue Reports verarbeitet, %d bereits bekannte in Papierkorb, %d Moves fehlgeschlagen.",
        total_new, total_trash, total_skip,
    )


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    args = _parse_args()
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        init_db(conn)
        if args.rescan:
            conn.execute("UPDATE folder_state SET last_uid = 0, delta_link = NULL")
            conn.commit()
            log.info("Rescan: Zustand für alle Ordner zurückgesetzt.")
        if args.imap:
            process_mailbox(conn)
        else:
            process_mailbox_exchange(conn)
    except KeyboardInterrupt:
        log.info("Abgebrochen.")
    except Exception:
        log.exception("Unbehandelter Fehler")
        raise
    finally:
        conn.close()


if __name__ == '__main__':
    main()
