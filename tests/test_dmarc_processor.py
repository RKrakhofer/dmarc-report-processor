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
