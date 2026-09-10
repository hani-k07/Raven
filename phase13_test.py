import os
import sqlite3
import json
from pathlib import Path
from datetime import datetime
from log_parser import _parse_web_server_logs

# Mock DB
DB_FILE = "test_web_logs.db"
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

import log_parser
log_parser.DB_PATH = Path(DB_FILE)

def setup_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE threats (id INTEGER PRIMARY KEY, timestamp TEXT, source_ip TEXT, event_type TEXT, raw_log TEXT, severity TEXT, ai_analysis TEXT, recommendation TEXT, alerted BOOLEAN)")
    cursor.execute("CREATE TABLE ip_allowlist (ip TEXT PRIMARY KEY, reason TEXT, added_at TEXT)")
    conn.commit()
    conn.close()

# Create dummy log file
log_content = (
    '192.168.1.10 - - [10/Sep/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123 "-" "Mozilla/5.0"\n'
    '192.168.1.11 - - [10/Sep/2026:10:01:00 +0000] "POST /login HTTP/1.1" 200 456 "-" "Mozilla/5.0"\n'
    '192.168.1.12 - - [10/Sep/2026:10:02:00 +0000] "GET /index.html HTTP/1.1" 200 1000 "-" "Mozilla/5.0"\n'
    '192.168.1.13 - - [10/Sep/2026:10:03:00 +0000] "GET /wp-admin HTTP/1.1" 403 78 "-" "Curl/7.68.0"\n'
    '192.168.1.14 - - [10/Sep/2026:10:04:00 +0000] "GET /nonexistent HTTP/1.1" 404 123 "-" "Mozilla/5.0"\n'
)
log_path = "test_web.log"
with open(log_path, "w") as f:
    f.write(log_content)

if __name__ == "__main__":
    setup_db()
    print("Testing web server log parsing...")
    results = _parse_web_server_logs(log_path)
    print(f"Parsed {len(results)} suspicious events.")
    for r in results:
        print(f"Event: {r['event_type']} | IP: {r['source_ip']} | Log: {r['raw_log']}")

    assert len(results) >= 3 # /admin, /wp-admin, /nonexistent
    print("\nSUCCESS: Web log parsing works.")

    os.remove(log_path)
    os.remove(DB_FILE)
