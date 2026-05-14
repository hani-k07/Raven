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
    conn.commit()
    conn.close()
    print("All tables dropped.")
    init_db()
    print("Database reset complete.")

if __name__ == "__main__":
    init_db()
