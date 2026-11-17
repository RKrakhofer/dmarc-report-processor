"""Shared fixtures for dmarc-report-processor tests."""

import sqlite3
import time

import pytest


@pytest.fixture()
def conn(tmp_path):
    """Initialized in-memory SQLite DB with all DMARC tables."""
    import dmarc_processor as dp

    path = str(tmp_path / "test.db")
    c = sqlite3.connect(path)
    dp.init_db(c)
    yield c
    c.close()


@pytest.fixture()
def populated_db(conn):
    """DB with one complete report (spoofing + own mail + auth results)."""
    import dmarc_processor as dp

    now = int(time.time())
    mid = "<test-populated@example.com>"
    conn.execute("INSERT INTO processed_messages (message_id) VALUES (?)", (mid,))

    dp.parse_dmarc_xml(POPULATED_XML.encode(), mid, conn)
    conn.commit()
    return conn


@pytest.fixture()
def bypass_db(conn):
    """DB mit SPF-Alignment-Bypass, eigener Mail, externem Newsletter und klassischem Spoof."""
    now = int(time.time())
    mid = "<bypass@example.com>"
    conn.execute("INSERT INTO processed_messages (message_id) VALUES (?)", (mid,))
    conn.execute("""
        INSERT INTO reports (message_id, org_name, report_id, date_begin, date_end,
                             domain, adkim, aspf, policy_p, policy_sp, policy_pct)
        VALUES (?, 'Google', 'BYPASS1', ?, ?, 'krakhofer.org', 'r', 'r', 'reject', 'reject', 100)
    """, (mid, now - 86400, now))
    report_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def add_record(ip, count, disposition, dkim, spf, header_from,
                   spf_domain, dkim_domain, dkim_result=None, spf_result=None):
        cur = conn.execute("""
            INSERT INTO report_records (report_db_id, source_ip, count, disposition,
                                        dkim_eval, spf_eval, header_from, envelope_from)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (report_id, ip, count, disposition, dkim, spf, header_from, header_from))
        rid = cur.lastrowid
        conn.execute(
            "INSERT INTO auth_spf_results (record_id, domain, scope, result) VALUES (?, ?, 'envelope', ?)",
            (rid, spf_domain, spf_result or spf),
        )
        conn.execute(
            "INSERT INTO auth_dkim_results (record_id, domain, selector, result) VALUES (?, ?, 'sel', ?)",
            (rid, dkim_domain, dkim_result or dkim),
        )
        return rid

    # Angriff: SPF passt auf krakhofer.org-Subdomain, DKIM fehlt, Mail wurde zugestellt
    add_record('159.253.44.48', 2475, 'none', 'fail', 'pass',
               'office.gov.krakhofer.org', 'office.gov.krakhofer.org', 'office.gov.krakhofer.org')
    # Legitime eigene Mail – liefert die eigene IP über DKIM-pass
    add_record('192.99.58.238', 3, 'none', 'pass', 'pass',
               'info@krakhofer.org', 'krakhofer.org', 'krakhofer.org')
    # Externer Newsletter: SPF-pass, aber header_from nicht unsere Domain → kein Treffer
    add_record('203.0.113.77', 12, 'none', 'fail', 'pass',
               'news@external.example', 'external.example', 'external.example')
    # Klassischer Spoof:DKIM✗ + SPF✗, bereits blockiert
    add_record('47.43.1.1', 10, 'reject', 'fail', 'fail',
               'fake@x.krakhofer.org', 'x.krakhofer.org', 'x.krakhofer.org')
    # Eigene IP mit ungewöhnlichem From – darf nicht als fremd gemeldet werden
    add_record('192.99.58.238', 5, 'none', 'fail', 'pass',
               'own-sub.krakhofer.org', 'own-sub.krakhofer.org', 'own-sub.krakhofer.org')
    conn.commit()
    return conn


POPULATED_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<feedback xmlns="urn:oasis:names:tc:dmarc:1.0">
  <report_metadata>
    <org_name>Google</org_name>
    <email>abuse@google.com</email>
    <report_id>G1</report_id>
    <date_range><begin>1704067200</begin><end>1704153600</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>krakhofer.org</domain>
    <adkim>r</adkim><aspf>r</aspf>
    <p>reject</p><sp>reject</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>47.43.1.1</source_ip>
      <count>10</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
        <reason>
          <type>provider_policy</type>
          <comment>spoof detected</comment>
        </reason>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_to>user@krakhofer.org</envelope_to>
      <header_from>fake@xpvfyeztqo.krakhofer.org</header_from>
      <envelope_from>evil@attacker.net</envelope_from>
    </identifiers>
    <auth_results>
      <dkim><domain>krakhofer.org</domain><selector>sel</selector><result>fail</result><human_result>signature verification failed</human_result></dkim>
      <spf><domain>krakhofer.org</domain><scope>envelope</scope><result>fail</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.50</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_to>user@krakhofer.org</envelope_to>
      <header_from>info@krakhofer.org</header_from>
      <envelope_from>info@krakhofer.org</envelope_from>
    </identifiers>
    <auth_results>
      <dkim><domain>krakhofer.org</domain><selector>google</selector><result>pass</result></dkim>
      <spf><domain>krakhofer.org</domain><scope>envelope</scope><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>
"""
