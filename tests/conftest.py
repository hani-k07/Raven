import pytest
import sqlite3
import os
from pathlib import Path
import db_init

@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Provides a temporary SQLite database for testing."""
    db_file = tmp_path / "test_raven.db"

    # Monkeypatch DB_PATH in all relevant modules
    monkeypatch.setattr("db_init.DB_PATH", db_file)
    monkeypatch.setattr("log_parser.DB_PATH", db_file)
    monkeypatch.setattr("fim.DB_PATH", db_file)
    monkeypatch.setattr("process_monitor.DB_PATH", db_file)
    monkeypatch.setattr("alerter.DB_PATH", db_file)

    # Initialize the database
    db_init.init_db()

    return str(db_file)
