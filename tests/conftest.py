"""Shared fixtures for dmarc-report-processor tests."""

import sqlite3

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
