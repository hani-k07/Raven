import sqlite3
import os
import pytest
from datetime import datetime
from log_parser import _insert_threat, _is_ip_allowlisted
from analyzer import analyze_threat

@pytest.fixture
def db_setup(tmp_path, monkeypatch):
    db_file = tmp_path / "test_raven_p9.db"
    db_path_str = str(db_file)

    # Monkeypatch the central DB_PATH in db_init
    import db_init
    monkeypatch.setattr(db_init, "DB_PATH", db_file)

    # Create tables
    conn = sqlite3.connect(db_path_str)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            event_type TEXT,
            raw_log TEXT,
            severity TEXT,
            ai_analysis TEXT,
            recommendation TEXT,
            alerted BOOLEAN,
            false_positive BOOLEAN DEFAULT 0
        );
    """)
    cursor.execute("""
        CREATE TABLE ip_allowlist (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            added_at TEXT
        );
    """)
    conn.commit()
    conn.close()
    return db_path_str

def test_allowlist_downgrade(db_setup):
    print("Testing allowlist downgrade logic...")
    db_file = db_setup
    ip = "1.2.3.4"

    # 1. Add IP to allowlist
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ip_allowlist (ip, reason, added_at) VALUES (?, ?, ?)",
                   (ip, "Test allowlist", datetime.now().isoformat()))
    conn.commit()
    conn.close()

    # 2. Insert threat from this IP
    analysis = {"severity": "Critical", "explanation": "Dangerous attack", "recommendation": "Block IP"}
    _insert_threat(datetime.now().isoformat(), ip, "SSH Brute Force", "Failed password...", analysis)

    # 3. Verify it was downgraded to Low
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT severity, ai_analysis FROM threats WHERE source_ip=?", (ip,))
    row = cursor.fetchone()
    conn.close()

    if row:
        severity, analysis_text = row
        print(f"Result -> Severity: {severity}, Analysis: {analysis_text}")
        assert severity == "Low"
        assert "[ALLOWLISTED]" in analysis_text
        print("SUCCESS: Downgrade test passed.")
    else:
        pytest.fail("No threat found in DB.")
