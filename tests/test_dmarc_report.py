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
