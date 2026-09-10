import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "raven.db"

def init_db():
    """Initializes the SQLite database with required tables. Safe to call on every startup — does NOT drop existing data."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            event_type TEXT,
            raw_log TEXT,
            severity TEXT,
            ai_analysis TEXT,
            recommendation TEXT,
            alerted BOOLEAN
        );
    """)

    # Add indexes for performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_alerted ON threats(alerted);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_ip ON threats(source_ip);")

    # Add false_positive column if missing
    try:
        cursor.execute("ALTER TABLE threats ADD COLUMN false_positive BOOLEAN DEFAULT 0")
    except sqlite3.OperationalError:
        pass # Column already exists

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_allowlist (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            added_at TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_baseline (
            port INTEGER PRIMARY KEY,
            process_name TEXT,
            first_seen TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            check_name TEXT,
            status TEXT,
            detail TEXT,
            timestamp TEXT
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS honeypot_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            attacker_ip TEXT,
            port INTEGER,
            payload TEXT
        );
    """)

    conn.commit()
    conn.close()
    print(f"Database ready at {DB_PATH}")

def reset_db():
    """Drops and recreates all tables. FOR TESTING ONLY — destroys all data."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS threats;")
    cursor.execute("DROP TABLE IF EXISTS audit_results;")
    cursor.execute("DROP TABLE IF EXISTS honeypot_events;")
    cursor.execute("DROP TABLE IF EXISTS process_baseline;")
    cursor.execute("DROP TABLE IF EXISTS ip_allowlist;")
    conn.commit()
    conn.close()
    print("All tables dropped.")
    init_db()
    print("Database reset complete.")

if __name__ == "__main__":
    init_db()
