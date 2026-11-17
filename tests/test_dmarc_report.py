"""Unit tests for dmarc_report.py helper functions."""

import argparse
import ipaddress
import sqlite3

import pytest
import dmarc_report as dr


# ── _glob_to_sql_like ────────────────────────────────────────────────

@pytest.mark.parametrize("glob_like,expected", [
    ("*", "%"),
    ("*.google.com", "%.google.com"),
    ("a?c", "a_c"),
    ("a%c", "a\\%c"),
    ("a_b", "a\\_b"),
    ("plain", "plain"),
])
def test_glob_to_sql_like(glob_like, expected):
    assert dr._glob_to_sql_like(glob_like) == expected


# ── _timeline_type ───────────────────────────────────────────────────

@pytest.mark.parametrize("value,count,unit", [
    ("30d", 30, "d"),
    ("4w", 4, "w"),
    ("12m", 12, "m"),
    ("2y", 2, "y"),
])
def test_timeline_type_valid(value, count, unit):
    assert dr._timeline_type(value) == (count, unit)


@pytest.mark.parametrize("bad", ["", "d", "30x", "abc", "30 days", "d30"])
def test_timeline_type_invalid(bad):
    with pytest.raises(argparse.ArgumentTypeError):
        dr._timeline_type(bad)


# ── _dns_exists (öffentlicher Resolver, kein Split-Horizon) ────────────

def test_dns_exists_uses_public_resolver(monkeypatch):
    import dns.resolver as dns_resolver

    instances = []

    class FakeResolver:
        def __init__(self, configure=True):
            self.configure = configure
            self.nameservers = []
            self.lifetime = None
            self.calls = []
            instances.append(self)

        def resolve(self, hostname, rdtype, **kwargs):
            self.calls.append((hostname, rdtype, kwargs.get('lifetime')))
            return ['answer']

    monkeypatch.setattr(dns_resolver, 'Resolver', FakeResolver)

    def forbidden(*args, **kwargs):
        raise AssertionError('socket.getaddrinfo darf nicht verwendet werden')

    monkeypatch.setattr(dr.socket, 'getaddrinfo', forbidden)

    assert dr._dns_exists('Example.COM') is True
    assert len(instances) == 1
    resolver = instances[0]
    assert resolver.configure is False
    assert resolver.nameservers == list(dr.PUBLIC_DNS_SERVERS)
    assert resolver.calls == [('example.com', 'A', dr.DNS_TIMEOUT)]


def test_dns_exists_nxdomain(monkeypatch):
    import dns.resolver as dns_resolver

    class FakeResolver:
        def __init__(self, configure=True):
            self.nameservers = []

        def resolve(self, hostname, rdtype, **kwargs):
            raise dns_resolver.NXDOMAIN()

    monkeypatch.setattr(dns_resolver, 'Resolver', FakeResolver)
    assert dr._dns_exists('nope.invalid') is False


def test_dns_exists_invalid_hostname_never_queries(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('DNS darf für ungültige Hostnamen nicht abgefragt werden')

    monkeypatch.setattr(dr, '_resolve_public', forbidden, raising=False)
    monkeypatch.setattr(dr.socket, 'getaddrinfo', forbidden)
    for bad in ('evil; rm -rf /', '-leading.example.com', 'a' * 300, '', None):
        assert dr._dns_exists(bad) is False


# ── Domain-/IP-Marshalling ────────────────────────────────────────────

@pytest.mark.parametrize("host,expected", [
    ('gov.krakhofer.org', True),
    ('krakhofer.org', True),
    ('notkrakhofer.org', False),
    ('KRakhofer.ORG.', True),
    (None, False),
    ('', False),
])
def test_in_org_domain(host, expected):
    assert dr._in_org_domain(host, ['krakhofer.org']) is expected


def test_in_org_domain_uses_configured_default(monkeypatch):
    monkeypatch.setattr(dr, 'MY_DOMAINS', ['krakhofer.org'])
    assert dr._in_org_domain('x.krakhofer.org') is True


def test_parse_ip_ranges_valid():
    ranges = dr._parse_ip_ranges('192.0.2.0/24, 2001:db8::/32, 198.51.100.7')
    assert len(ranges) == 3
    assert ipaddress.ip_address('192.0.2.5') in ranges[0]
    assert ipaddress.ip_address('2001:db8::1') in ranges[1]
    assert ipaddress.ip_address('198.51.100.7') in ranges[2]


@pytest.mark.parametrize("bad", ['192.0.2.0/33', 'not-an-ip', '10.0.0.0/8, broken'])
def test_parse_ip_ranges_invalid(bad):
    with pytest.raises(ValueError):
        dr._parse_ip_ranges(bad)


def test_is_foreign_ip():
    ranges = dr._parse_ip_ranges('192.0.2.0/24')
    own = {'198.51.100.7'}
    assert dr._is_foreign_ip('198.51.100.7', own, ranges) is False
    assert dr._is_foreign_ip('192.0.2.9', own, ranges) is False
    assert dr._is_foreign_ip('203.0.113.9', own, ranges) is True
    assert dr._is_foreign_ip('nonsense', own, ranges) is True
    assert dr._is_foreign_ip(None, own, ranges) is True
    assert dr._is_foreign_ip('', own, ranges) is True


def test_collect_own_ips(bypass_db):
    bypass_db.row_factory = sqlite3.Row
    ips = dr._collect_own_ips(bypass_db)
    assert '192.99.58.238' in ips
    assert '159.253.44.48' not in ips


# ── fmt_row / section ────────────────────────────────────────────────

def test_fmt_row():
    r = {"a": "1", "b": None, "c": "3"}
    out = dr.fmt_row(r, "a", "b", "c")
    assert "a=1" in out
    assert "c=3" in out
    assert "b=" not in out


def test_section(capsys):
    dr.section("TEST SECTION")
    captured = capsys.readouterr()
    assert "TEST SECTION" in captured.out
    assert "=" * 80 in captured.out


# ── run (empty DB) ───────────────────────────────────────────────────

def test_run_empty_db(conn, capsys):
    conn.row_factory = sqlite3.Row
    dr.run(conn)
    out = capsys.readouterr().out
    assert "Keine Daten." in out
    assert "Keine Probleme gefunden." in out
    assert "Keine blockierten Mails." in out


# ── run (populated DB) ───────────────────────────────────────────────

def test_run_populated(populated_db, capsys):
    populated_db.row_factory = sqlite3.Row
    # MY_DOMAINS needs to be set for the "own domain" filter
    dr.MY_DOMAINS = ["krakhofer.org"]
    dr.run(populated_db)
    out = capsys.readouterr().out
    assert "Google" in out          # org_name
    assert "krakhofer.org" in out  # domain
    assert "47.43.1.1" in out      # spoofing IP


# ── _print_assessment ────────────────────────────────────────────────

def test_print_assessment(populated_db, capsys, monkeypatch):
    populated_db.row_factory = sqlite3.Row
    dr.MY_DOMAINS = ["krakhofer.org"]
    # Prevent real DNS lookups
    monkeypatch.setattr(dr, "_dns_exists", lambda h: False)
    dr._print_assessment(populated_db)
    out = capsys.readouterr().out
    assert "Spoofing-Versuche" in out
    assert "reject" in out  # policy


def test_assessment_detects_alignment_bypass_and_delivered(bypass_db, capsys, monkeypatch):
    bypass_db.row_factory = sqlite3.Row
    dr.MY_DOMAINS = ['krakhofer.org']
    monkeypatch.setattr(dr, '_dns_exists', lambda h: False)
    dr._print_assessment(bypass_db)
    out = capsys.readouterr().out
    assert 'SPF-Alignment-Bypass' in out
    assert '2475' in out
    assert '159.253.44.48' in out
    assert 'disposition=none' in out
    assert 'zugestellt' in out
    # externer Newsletter darf nicht als unsere Domain gemeldet werden
    assert 'external.example' not in out


def test_assessment_no_false_bypass_without_foreign_delivery(populated_db, capsys, monkeypatch):
    populated_db.row_factory = sqlite3.Row
    dr.MY_DOMAINS = ['krakhofer.org']
    monkeypatch.setattr(dr, '_dns_exists', lambda h: False)
    dr._print_assessment(populated_db)
    out = capsys.readouterr().out
    assert 'SPF-Alignment-Bypass' not in out
    assert 'disposition=none' not in out


def test_assessment_reports_existing_spoof_subdomain(populated_db, capsys, monkeypatch):
    populated_db.row_factory = sqlite3.Row
    dr.MY_DOMAINS = ['krakhofer.org']
    monkeypatch.setattr(dr, '_dns_exists', lambda h: True)
    dr._print_assessment(populated_db)
    out = capsys.readouterr().out
    assert 'ECHTES PROBLEM' in out
    assert 'xpvfyeztqo.krakhofer.org' in out


def test_assessment_respects_my_ip_ranges(bypass_db, capsys, monkeypatch):
    bypass_db.row_factory = sqlite3.Row
    dr.MY_DOMAINS = ['krakhofer.org']

    monkeypatch.setattr(dr, 'MY_IP_RANGES', ())
    dr._print_assessment(bypass_db)
    out = capsys.readouterr().out
    assert 'SPF-Alignment-Bypass' in out

    monkeypatch.setattr(dr, 'MY_IP_RANGES', (ipaddress.ip_network('159.253.44.48/32'),))
    dr._print_assessment(bypass_db)
    out = capsys.readouterr().out
    assert 'SPF-Alignment-Bypass' not in out
    assert 'zugestellt' not in out


def test_assessment_reports_delivered_without_bypass(conn, capsys):
    import time

    conn.row_factory = sqlite3.Row
    dr.MY_DOMAINS = ['krakhofer.org']
    now = int(time.time())
    mid = '<delivered@example.com>'
    conn.execute("INSERT INTO processed_messages (message_id) VALUES (?)", (mid,))
    conn.execute("""
        INSERT INTO reports (message_id, org_name, report_id, date_begin, date_end,
                             domain, policy_p)
        VALUES (?, 'Google', 'DEL1', ?, ?, 'krakhofer.org', 'reject')
    """, (mid, now - 60, now))
    report_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("""
        INSERT INTO report_records (report_db_id, source_ip, count, disposition,
                                    dkim_eval, spf_eval, header_from)
        VALUES (?, '203.0.113.99', 4, 'none', 'pass', 'fail', 'info@krakhofer.org')
    """, (report_id,))
    conn.commit()
    dr._print_assessment(conn)
    out = capsys.readouterr().out
    assert 'zugestellt (disposition=none)' in out
    assert 'SPF-Alignment-Bypass' not in out


# ── _print_timeline ──────────────────────────────────────────────────

def test_print_timeline(populated_db, capsys):
    populated_db.row_factory = sqlite3.Row
    dr.MY_DOMAINS = ["krakhofer.org"]
    dr._print_timeline(populated_db, 365, "d")
    out = capsys.readouterr().out
    assert "REPUTATION-TIMELINE" in out


# ── _print_arc_overrides ─────────────────────────────────────────────

def test_print_arc_overrides(populated_db, capsys):
    populated_db.row_factory = sqlite3.Row
    dr._print_arc_overrides(populated_db)
    out = capsys.readouterr().out
    # first record has reason_type set
    assert "provider_policy" in out


# ── _print_envelope_domain_list ──────────────────────────────────────

def test_print_envelope_domain_list(populated_db, capsys):
    populated_db.row_factory = sqlite3.Row
    dr._print_envelope_domain_list(populated_db, "*")
    out = capsys.readouterr().out
    assert "ENVELOPE-TO DOMAINS" in out
    assert "user@krakhofer.org" in out


# ── _print_envelope_to_detail ────────────────────────────────────────

def test_print_envelope_to_detail(populated_db, capsys):
    populated_db.row_factory = sqlite3.Row
    dr._print_envelope_to_detail(populated_db, "user@krakhofer.org")
    out = capsys.readouterr().out
    assert "DETAILS für envelope_to" in out
    assert "DKIM-Auth" in out
    assert "SPF-Auth" in out
