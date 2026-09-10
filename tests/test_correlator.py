import pytest
import sqlite3
from correlator import correlate, escalate_severity

def test_escalate_severity():
    # Test severity transitions
    assert escalate_severity("Low", 5) == "Medium"
    assert escalate_severity("Medium", 5) == "High"
    assert escalate_severity("High", 5) == "Critical"
    assert escalate_severity("Critical", 5) == "Critical"

def test_correlate_logic(temp_db):
    # Seed temp DB with threats from the same IP
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    # 3 threats from 1.1.1.1
    for i in range(3):
        cursor.execute(
            "INSERT INTO threats (timestamp, source_ip, event_type, severity, alerted) VALUES (?, ?, ?, ?, ?)",
            (f"2026-09-10T10:00:0{i}", "1.1.1.1", "SSH_BRUTE_FORCE", "Medium", 0)
        )
    conn.commit()
    conn.close()

    # Run correlation
    correlated = correlate()
    # Should find the IP and potentially escalate
    assert any(c["source_ip"] == "1.1.1.1" for c in correlated)
