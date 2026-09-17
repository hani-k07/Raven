import pytest
import requests
import os
import sqlite3
from unittest.mock import patch, MagicMock
from pathlib import Path
from datetime import datetime

from analyzer import analyze_threat
from log_parser import _parse_linux_logs, _parse_web_server_logs
import security_check

# --- 1. Log OOM / Memory Exhaustion ---
def test_log_parser_memory_exhaustion(tmp_path, monkeypatch):
    """Demonstrate that readlines() can be a memory bottleneck."""
    log_file = tmp_path / "huge.log"
    # Write 100,000 lines to simulate a large log
    with open(log_file, "w") as f:
        for i in range(100000):
            f.write(f"Failed password for root from 1.2.3.{i%255} port 1234 ssh2\n")
    
    monkeypatch.setattr("config.LOG_FILE_LINUX", str(log_file))
    
    # This should run but if it were 10M lines, it would crash.
    # For a demo, we just check it processes correctly but note the readlines() usage.
    res = _parse_linux_logs()
    assert len(res) <= 50  # Limited by the 'processed' counter

# --- 2. Encoding Issues ---
def test_log_parser_encoding_failure(tmp_path, monkeypatch):
    """Check if log_parser fails on non-UTF-8 encoding."""
    log_file = tmp_path / "latin1.log"
    # Write content in latin-1
    with open(log_file, "wb") as f:
        f.write("Failed password for root from 1.2.3.4 port 1234 ssh2\n".encode("latin-1"))
        f.write("Invalid user \xef from 1.2.3.4\n".encode("latin-1")) # \xef is not valid utf-8
        
    monkeypatch.setattr("config.LOG_FILE_LINUX", str(log_file))
    
    # This will likely raise UnicodeDecodeError in the current implementation
    try:
        _parse_linux_logs()
    except UnicodeDecodeError:
        pytest.fail("Log parser crashed on non-UTF-8 encoding!")
    except Exception as e:
        print(f"Caught expected error or handled: {e}")

# --- 3. API Timeouts/Network Failures ---
@patch("requests.post")
def test_analyze_threat_timeout(mock_post):
    """Verify that API timeouts are handled gracefully."""
    mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")
    
    import os
    os.environ["OPENROUTER_API_KEY"] = "fake_key"
    
    # Should not crash, should fallback to Ollama or static
    res = analyze_threat("Event", "Log", "1.1.1.1")
    assert "severity" in res
    assert res["severity"] in ["Low", "Medium", "High", "Critical"]

# --- 4. Missing API Keys ---
def test_analyze_threat_no_keys():
    """Verify behavior when API keys are completely missing."""
    import os
    if "OPENROUTER_API_KEY" in os.environ: del os.environ["OPENROUTER_API_KEY"]
    
    # Mock config to be empty
    with patch("config.OPENROUTER_API_KEY", None), \
         patch("config.ABUSEIPDB_API_KEY", None):
        res = analyze_threat("Event", "Log", "1.1.1.1")
        assert res["severity"] == "Medium" # static fallback
        assert "unavailable" in res["explanation"]

# --- 5. Log Flooding / DB Volume ---
def test_correlator_volume(tmp_path, monkeypatch):
    """Check correlator performance with a large number of threats."""
    db_file = tmp_path / "volume.db"
    import db_init
    monkeypatch.setattr("db_init.DB_PATH", db_file)
    db_init.init_db()
    
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    # Insert 1000 threats from the same IP
    for i in range(1000):
        cursor.execute(
            "INSERT INTO threats (timestamp, source_ip, event_type, severity, alerted) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), "1.1.1.1", "SSH_BRUTE_FORCE", "Low", 0)
        )
    conn.commit()
    conn.close()
    
    from correlator import correlate
    import time
    start = time.time()
    res = correlate()
    end = time.time()
    
    print(f"Correlation of 1000 events took {end-start:.4f}s")
    assert any(c["source_ip"] == "1.1.1.1" for c in res)
    assert (end-start) < 1.0 # Should be very fast

# --- 6. CI Security Check Failure ---
def test_security_check_detects_rogue_inserts(tmp_path, monkeypatch):
    """Verify security_check.py fails when unauthorized files use INSERT INTO threats."""
    rogue_file = tmp_path / "rogue.py"
    rogue_file.write_text("import sqlite3\ncursor.execute('INSERT INTO threats ...')")
    
    # Mock os.walk to return our rogue file
    def mock_walk(path):
        yield (str(tmp_path), [], [rogue_file.name])
        
    with patch("os.walk", side_effect=mock_walk):
        with pytest.raises(SystemExit) as e:
            security_check.check_security()
        assert e.value.code == 1
