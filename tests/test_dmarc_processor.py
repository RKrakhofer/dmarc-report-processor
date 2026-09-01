"""Unit tests for dmarc_processor.py helper functions and XML parser."""

import gzip
import io
import zipfile
from xml.etree.ElementTree import Element, SubElement

import pytest
import dmarc_processor as dp


# ── _strip_xml_namespaces ────────────────────────────────────────────

def test_strip_xml_namespaces_removes_decl():
    xml = b'<report xmlns="urn:oasis:names:tc:dmarc:1.0"><range>x</range></report>'
    out = dp._strip_xml_namespaces(xml)
    assert b"xmlns" not in out
    assert b"<range>" in out


def test_strip_xml_namespaces_removes_prefixed_tags():
    xml = b'<dm:feedback xmlns:dm="urn:dm"><dm:range>x</dm:range></dm:feedback>'
    out = dp._strip_xml_namespaces(xml)
    assert b"dm:" not in out
    assert b"<feedback>" in out


def test_strip_xml_namespaces_noop():
    xml = b'<report><range>abc</range></report>'
    assert dp._strip_xml_namespaces(xml) == xml


# ── _text / _int ─────────────────────────────────────────────────────

def _el(*children: str, text=None) -> Element:
    """Helper: build Element with optional text children."""
    root = Element("root")
    for tag, txt in [c.split("=", 1) for c in children]:
        SubElement(root, tag).text = txt
    return root


def test_text_found():
    el = _el("b=hello")
    assert dp._text(el, "b") == "hello"


def test_text_missing_returns_default():
    el = Element("root")
    assert dp._text(el, "x", default="fallback") == "fallback"


def test_int_valid():
    el = _el("n=42")
    assert dp._int(el, "n") == 42


def test_int_invalid():
    el = _el("n=abc")
    assert dp._int(el, "n", default=0) == 0


# ── is_likely_dmarc_attachment ───────────────────────────────────────

@pytest.mark.parametrize("ct,fn,expected", [
    ("application/zip", "dmarc.xml.zip", True),
    ("text/xml", "report.xml", True),
    ("application/pdf", "doc.pdf", False),
    ("application/octet-stream", "data.bin", False),
    ("application/gzip", "dmarc.xml.gz", True),
])
def test_is_likely_dmarc_attachment(ct, fn, expected):
    assert dp.is_likely_dmarc_attachment(ct, fn) is expected


# ── try_extract_xml ──────────────────────────────────────────────────

def test_extract_direct_xml():
    data = b'<?xml version="1.0"?><feedback/>'
    assert dp.try_extract_xml(data, "report.xml", "text/xml") == data


def test_extract_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("report.xml", b"<feedback/>")
    out = dp.try_extract_xml(buf.getvalue(), "dmarc.zip", "application/zip")
    assert out == b"<feedback/>"


def test_extract_gzip():
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(b"<feedback/>")
    out = dp.try_extract_xml(buf.getvalue(), "dmarc.gz", "application/gzip")
    assert out == b"<feedback/>"


def test_extract_invalid_returns_none():
    assert dp.try_extract_xml(b"not a zip", "x.zip", "application/zip") is None
    assert dp.try_extract_xml(b"not a gz", "x.gz", "application/gzip") is None


# ── parse_dmarc_xml ──────────────────────────────────────────────────

SAMPLE_DMRFC = """\
<?xml version="1.0" encoding="UTF-8" ?>
<feedback xmlns="urn:oasis:names:tc:dmarc:1.0">
  <report_metadata>
    <org_name>Example Corp</org_name>
    <email>postmaster@example.com</email>
    <report_id>R1</report_id>
    <date_range><begin>1704067200</begin><end>1704153600</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>s</adkim><aspf>s</aspf>
    <p>reject</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>1.2.3.4</source_ip>
      <count>5</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>pass</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_to>dest@example.com</envelope_to>
      <header_from>attacker@spoof.example</header_from>
      <envelope_from>evil@attacker.net</envelope_from>
    </identifiers>
    <auth_results>
      <dkim><domain>attacker.net</domain><selector>sel1</selector><result>fail</result></dkim>
      <spf><domain>attacker.net</domain><scope>envelope</scope><result>fail</result></spf>
    </auth_results>
  </record>
</feedback>
"""


def test_parse_full_inserts_records(conn):
    # must insert into processed_messages first (FK constraint)
    conn.execute("INSERT INTO processed_messages (message_id) VALUES (?)", ("msg-1",))
    conn.commit()

    n = dp.parse_dmarc_xml(SAMPLE_DMRFC.encode(), "msg-1", conn)
    assert n == 1

    row = conn.execute(
        "SELECT domain, policy_p, report_id FROM reports WHERE message_id='msg-1'"
    ).fetchone()
    assert row[0] == "example.com"
    assert row[1] == "reject"
    assert row[2] == "R1"

    rec = conn.execute("SELECT source_ip, count, dkim_eval, spf_eval FROM report_records").fetchone()
    assert rec[0] == "1.2.3.4"
    assert rec[1] == 5
    assert rec[2] == "pass"
    assert rec[3] == "fail"

    assert conn.execute("SELECT COUNT(*) FROM auth_dkim_results").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM auth_spf_results").fetchone()[0] == 1


def test_parse_non_feedback_returns_zero(conn):
    conn.execute("INSERT INTO processed_messages (message_id) VALUES (?)", ("msg-2",))
    conn.commit()
    assert dp.parse_dmarc_xml(b"<not_dmarc/>", "msg-2", conn) == 0


def test_parse_malformed_returns_zero(conn):
    conn.execute("INSERT INTO processed_messages (message_id) VALUES (?)", ("msg-3",))
    conn.commit()
    assert dp.parse_dmarc_xml(b"<broken", "msg-3", conn) == 0


# ── _parse_args ──────────────────────────────────────────────────────

def test_parse_args_imap(monkeypatch):
    monkeypatch.setattr("sys.argv", ["prog", "--imap"])
    args = dp._parse_args()
    assert args.imap is True
    assert args.xchg is False


def test_parse_args_xchg(monkeypatch):
    monkeypatch.setattr("sys.argv", ["prog", "--xchg", "-q"])
    args = dp._parse_args()
    assert args.xchg is True
    assert args.quiet is True


def test_parse_args_missing_mode(monkeypatch):
    monkeypatch.setattr("sys.argv", ["prog"])
    with pytest.raises(SystemExit):
        dp._parse_args()


# ── _load / _save_folder_state ───────────────────────────────────────

def test_folder_state_roundtrip(conn):
    assert dp._load_folder_state(conn, "INBOX") == (0, 0)

    dp._save_folder_state(conn, "INBOX", 12345, 99)
    assert dp._load_folder_state(conn, "INBOX") == (12345, 99)

    dp._save_folder_state(conn, "INBOX", 12345, 200)
    assert dp._load_folder_state(conn, "INBOX") == (12345, 200)


# ── _load / _save_xchg_delta_link ───────────────────────────────────

def test_xchg_delta_link_roundtrip(conn):
    assert dp._load_xchg_delta_link(conn, "xchg:Inbox") is None

    dp._save_xchg_delta_link(conn, "xchg:Inbox", "https://graph/delta/123")
    assert dp._load_xchg_delta_link(conn, "xchg:Inbox") == "https://graph/delta/123"

    dp._save_xchg_delta_link(conn, "xchg:Inbox", "https://graph/delta/456")
    assert dp._load_xchg_delta_link(conn, "xchg:Inbox") == "https://graph/delta/456"


# ── _move_to_trash ───────────────────────────────────────────────────

class FakeIMAP:
    def __init__(self, move_ok=True, copy_ok=True):
        self._move_ok = move_ok
        self._copy_ok = copy_ok
        self.calls: list = []

    def uid(self, cmd, *args):
        self.calls.append((cmd, args))
        if cmd == "MOVE":
            return ("OK" if self._move_ok else "NO", [b""])
        if cmd == "COPY":
            return ("OK" if self._copy_ok else "NO", [b""])
        return ("OK", [b""])

    def expunge(self):
        self.calls.append(("EXPUNGE",))


def test_move_to_trash_via_move():
    fake = FakeIMAP(move_ok=True)
    assert dp._move_to_trash(fake, b"123", "Trash") is True
    assert fake.calls[0][0] == "MOVE"


def test_move_to_trash_fallback_copy():
    fake = FakeIMAP(move_ok=False, copy_ok=True)
    assert dp._move_to_trash(fake, b"123", "Trash") is True
    cmds = [c[0] for c in fake.calls]
    assert "COPY" in cmds
    assert "EXPUNGE" in cmds


def test_move_to_trash_fails():
    fake = FakeIMAP(move_ok=False, copy_ok=False)
    assert dp._move_to_trash(fake, b"123", "Trash") is False


# ── process_message ──────────────────────────────────────────────────

def test_process_message_with_xml_part(conn):
    """Build a real MIME message with a DMARC XML attachment."""
    import email
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
    from email.mime.text import MIMEText

    msg = MIMEMultipart()
    msg["Message-ID"] = "<msg-proc@test>"
    msg.attach(MIMEText("DMARC report", "plain"))

    part = MIMEBase("application", "xml")
    part.set_payload(SAMPLE_DMRFC.encode())
    part.add_header("Content-Disposition", "attachment; filename=\"dmarc.xml\"")
    msg.attach(part)

    # need to re-parse to get raw bytes
    raw = msg.as_bytes()
    from email.parser import BytesParser
    from email import policy as ep
    parsed = BytesParser(policy=ep.default).parsebytes(raw)

    conn.execute("INSERT INTO processed_messages (message_id) VALUES (?)", ("<msg-proc@test>",))
    conn.commit()

    total = dp.process_message(parsed, "<msg-proc@test>", conn)
    assert total >= 1


# ── _setup_file_logging ──────────────────────────────────────────────

def test_setup_file_logging(tmp_path, monkeypatch):
    log_file = tmp_path / "test.log"
    monkeypatch.setattr(dp, "LOG_FILE", log_file)
    dp._setup_file_logging()
    # handler was added, file may or may not exist yet (lazy)
    import logging
    handlers = logging.getLogger().handlers
    assert any(
        isinstance(h, logging.handlers.RotatingFileHandler)
        for h in handlers
    )


# ── try_extract_xml octet-stream ────────────────────────────────────

def test_extract_octet_stream_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dmarc.xml", b"<feedback/>")
    out = dp.try_extract_xml(buf.getvalue(), "data.bin", "application/octet-stream")
    assert out == b"<feedback/>"


def test_extract_octet_stream_gzip():
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(b"<feedback/>")
    out = dp.try_extract_xml(buf.getvalue(), "data.bin", "application/octet-stream")
    assert out == b"<feedback/>"


def test_extract_octet_stream_invalid():
    assert dp.try_extract_xml(b"garbage", "data.bin", "application/octet-stream") is None


# ── _xchg_get_token ─────────────────────────────────────────────────

def test_xchg_get_token_success(monkeypatch):
    class FakeMSAL:
        class ConfidentialClientApplication:
            def __init__(self, *a, **kw): pass
            def acquire_token_for_client(self, scopes=None):
                return {"access_token": "tok-123"}

    import types
    fake_msal = types.ModuleType("msal")
    fake_msal.ConfidentialClientApplication = FakeMSAL.ConfidentialClientApplication
    monkeypatch.setitem(__import__("sys").modules, "msal", fake_msal)

    assert dp._xchg_get_token() == "tok-123"


def test_xchg_get_token_failure(monkeypatch):
    class FakeMSAL:
        class ConfidentialClientApplication:
            def __init__(self, *a, **kw): pass
            def acquire_token_for_client(self, scopes=None):
                return {"error_description": "bad creds"}

    import types
    fake_msal = types.ModuleType("msal")
    fake_msal.ConfidentialClientApplication = FakeMSAL.ConfidentialClientApplication
    monkeypatch.setitem(__import__("sys").modules, "msal", fake_msal)

    with pytest.raises(RuntimeError, match="bad creds"):
        dp._xchg_get_token()


# ── _xchg_resolve_folder ────────────────────────────────────────────

class FakeResp:
    def __init__(self, data):
        self._data = data
    def raise_for_status(self): pass
    def json(self):
        return self._data

class FakeSession:
    def __init__(self, data):
        self._data = data
    def get(self, url, **kw):
        return FakeResp(self._data)


def test_xchg_resolve_well_known():
    assert dp._xchg_resolve_folder(None, "user", "Inbox") == "inbox"
    assert dp._xchg_resolve_folder(None, "user", "Sent Items") == "sentitems"
    assert dp._xchg_resolve_folder(None, "user", "Junk") == "junkemail"


def test_xchg_resolve_api_lookup():
    sess = FakeSession({"value": [{"id": "fid-1"}]})
    assert dp._xchg_resolve_folder(sess, "user@x.com", "Custom Folder") == "fid-1"


def test_xchg_resolve_not_found():
    sess = FakeSession({"value": []})
    with pytest.raises(ValueError, match="nicht gefunden"):
        dp._xchg_resolve_folder(sess, "user@x.com", "Nope")


# ── process_mailbox (IMAP missing config) ───────────────────────────

def test_process_mailbox_missing_config(monkeypatch):
    monkeypatch.setattr(dp, "IMAP_HOST", "")
    monkeypatch.setattr(dp, "IMAP_USER", "")
    monkeypatch.setattr(dp, "IMAP_PASSWORD", "")
    with pytest.raises(RuntimeError, match="IMAP"):
        dp.process_mailbox(None)


# ── process_mailbox_exchange (missing config) ───────────────────────

def test_process_mailbox_exchange_missing_config(monkeypatch):
    monkeypatch.setattr(dp, "XCHG_TENANT_ID", "")
    monkeypatch.setattr(dp, "XCHG_CLIENT_ID", "")
    monkeypatch.setattr(dp, "XCHG_CLIENT_SECRET", "")
    monkeypatch.setattr(dp, "XCHG_USER", "")
    with pytest.raises(RuntimeError, match="Exchange"):
        dp.process_mailbox_exchange(None)


# ── main ─────────────────────────────────────────────────────────────

def test_main_imap(monkeypatch, tmp_path):
    db = tmp_path / "main_test.db"
    monkeypatch.setattr(dp, "DB_PATH", db)
    monkeypatch.setattr("sys.argv", ["prog", "--imap"])
    monkeypatch.setattr(dp, "process_mailbox", lambda conn: None)
    monkeypatch.setattr(dp, "_setup_file_logging", lambda: None)
    dp.main()
    # DB file should exist after init_db
    assert db.exists()


def test_main_xchg(monkeypatch, tmp_path):
    db = tmp_path / "main_test2.db"
    monkeypatch.setattr(dp, "DB_PATH", db)
    monkeypatch.setattr("sys.argv", ["prog", "--xchg"])
    monkeypatch.setattr(dp, "process_mailbox_exchange", lambda conn: None)
    monkeypatch.setattr(dp, "_setup_file_logging", lambda: None)
    dp.main()
    assert db.exists()


# ── _process_folder (full IMAP mock) ────────────────────────────────

_DMRFC_MAIL = (
    b"MIME-Version: 1.0\r\n"
    b"Message-ID: <folder-test@example.com>\r\n"
    b"Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n"
    b"\r\n"
    b"--BOUND\r\n"
    b"Content-Type: application/xml; name=\"dmarc.xml\"\r\n"
    b"Content-Disposition: attachment; filename=\"dmarc.xml\"\r\n"
    b"\r\n"
    + b"<!DOCTYPE feedback><feedback>"
    b"<report_metadata><org_name>Mock</org_name><report_id>MF</report_id>"
    b"<date_range><begin>1</begin><end>2</end></date_range></report_metadata>"
    b"<policy_published><domain>x.com</domain><p>none</p></policy_published>"
    b"<record><row><source_ip>9.9.9.9</source_ip><count>1</count>"
    b"<policy_evaluated><disposition>none</disposition>"
    b"<dkim>pass</dkim><spf>pass</spf></policy_evaluated></row></record>"
    b"</feedback>"
    b"\r\n--BOUND--\r\n"
)


class MockIMAP:
    """Full IMAP protocol mock for _process_folder."""

    def __init__(self, mails: list[bytes]):
        self._mails = mails  # list of full raw MIME messages
        self._uid = 1
        self.calls: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def login(self, user, password):
        pass

    def select(self, folder, readonly=False):
        return ("OK", [b"1"])

    def status(self, folder, what):
        return ("OK", [b'("INBOX" (UIDVALIDITY 1))'])

    def uid(self, cmd, *args):
        self.calls.append(cmd)
        if cmd == "SEARCH":
            uids = b" ".join(str(i).encode() for i in range(1, len(self._mails) + 1))
            return ("OK", [uids])
        if cmd == "FETCH":
            uid_int = int(args[0])
            if b"HEADER.FIELDS" in str(args[1]).encode():
                # return just headers
                raw = self._mails[uid_int - 1]
                header_end = raw.index(b"\r\n\r\n")
                return ("OK", [(b"(UID %d FLAGS (\\Seen))" % uid_int, raw[:header_end])])
            else:
                return ("OK", [(b"(UID %d)" % uid_int, self._mails[uid_int - 1])])
        if cmd == "MOVE":
            return ("OK", [b""])
        if cmd == "COPY":
            return ("OK", [b""])
        if cmd == "STORE":
            return ("OK", [b""])
        return ("OK", [b""])

    def expunge(self):
        self.calls.append("EXPUNGE")


def test_process_folder_new_mail(conn):
    from email.parser import BytesParser
    from email import policy as ep

    imap = MockIMAP([_DMRFC_MAIL])
    parser = BytesParser(policy=ep.default)
    new, skip, trash = dp._process_folder(imap, "INBOX", parser, conn)
    assert new == 1
    assert skip == 0
    assert trash == 1  # moved to trash


def test_process_folder_no_new_mails(conn):
    """Second run: last_uid already saved, no new UIDs found → (0,0,0)."""
    from email.parser import BytesParser
    from email import policy as ep

    imap = MockIMAP([_DMRFC_MAIL])
    parser = BytesParser(policy=ep.default)
    dp._process_folder(imap, "INBOX", parser, conn)

    # Second run: same folder state, search starts after last_uid → no mails
    imap2 = MockIMAP([])  # no mails above last_uid
    new, skip, trash = dp._process_folder(imap2, "INBOX", parser, conn)
    assert (new, skip, trash) == (0, 0, 0)


def test_process_folder_select_fail():
    """If IMAP SELECT fails, return zeros."""
    class FailIMAP:
        def select(self, folder, readonly=False):
            return ("NO", [b"error"])
        def status(self, *a):
            return ("NO", [b""])

    from email.parser import BytesParser
    from email import policy as ep
    parser = BytesParser(policy=ep.default)
    assert dp._process_folder(FailIMAP(), "INBOX", parser, None) == (0, 0, 0)


def test_process_folder_uidvalidity_change(conn):
    """UIDVALIDITY change should trigger full rescan."""
    from email.parser import BytesParser
    from email import policy as ep

    # Save state with UIDVALIDITY=1
    dp._save_folder_state(conn, "INBOX", 1, 100)

    class ChangedUIDIMAP(MockIMAP):
        def status(self, folder, what):
            return ("OK", [b'("INBOX" (UIDVALIDITY 999))'])

    imap = ChangedUIDIMAP([_DMRFC_MAIL])
    parser = BytesParser(policy=ep.default)
    new, skip, trash = dp._process_folder(imap, "INBOX", parser, conn)
    assert new == 1
    # state should now have UIDVALIDITY=999
    assert dp._load_folder_state(conn, "INBOX")[0] == 999


# ── process_mailbox (full flow with mock IMAP) ──────────────────────

def test_process_mailbox_full_flow(conn, monkeypatch):
    monkeypatch.setattr(dp, "IMAP_HOST", "imap.test")
    monkeypatch.setattr(dp, "IMAP_PORT", 993)
    monkeypatch.setattr(dp, "IMAP_USER", "user@test")
    monkeypatch.setattr(dp, "IMAP_PASSWORD", "pass")
    monkeypatch.setattr(dp, "IMAP_FOLDER", ["INBOX"])
    monkeypatch.setattr(dp, "TRASH_FOLDER", "Trash")

    import imaplib
    mock_imap = MockIMAP([_DMRFC_MAIL])
    monkeypatch.setattr(imaplib, "IMAP4_SSL", lambda host, port, timeout=60: mock_imap)

    dp.process_mailbox(conn)
    assert conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 1


# ── main with rescan + quiet ─────────────────────────────────────────

def test_main_rescan(monkeypatch, tmp_path):
    db = tmp_path / "rescan.db"
    monkeypatch.setattr(dp, "DB_PATH", db)
    monkeypatch.setattr("sys.argv", ["prog", "--imap", "--rescan", "-q"])
    monkeypatch.setattr(dp, "process_mailbox", lambda conn: None)
    monkeypatch.setattr(dp, "_setup_file_logging", lambda: None)
    dp.main()
    assert db.exists()


def test_main_exception(monkeypatch, tmp_path):
    db = tmp_path / "exc.db"
    monkeypatch.setattr(dp, "DB_PATH", db)
    monkeypatch.setattr("sys.argv", ["prog", "--imap"])

    def boom(conn):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(dp, "process_mailbox", boom)
    monkeypatch.setattr(dp, "_setup_file_logging", lambda: None)
    with pytest.raises(RuntimeError, match="kaboom"):
        dp.main()
