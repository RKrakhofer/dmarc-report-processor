"""Unit tests for dmarc_report.py helper functions."""

import argparse
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


# ── _dns_exists ──────────────────────────────────────────────────────

def test_dns_exists_true(monkeypatch):
    def fake_getaddrinfo(*a, **kw):
        return [("1.2.3.4",)]

    monkeypatch.setattr(dr.socket, "getaddrinfo", fake_getaddrinfo)
    assert dr._dns_exists("example.com") is True


def test_dns_exists_false(monkeypatch):
    import socket as _socket

    def fake_getaddrinfo(*a, **kw):
        raise _socket.gaierror("no address")

    monkeypatch.setattr(dr.socket, "getaddrinfo", fake_getaddrinfo)
    assert dr._dns_exists("nonexistent.invalid") is False


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
