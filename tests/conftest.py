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
