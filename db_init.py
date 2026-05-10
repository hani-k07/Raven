import sqlite3
from pathlib import Path

def init_db():
    """Initializes the SQLite database with required tables."""
    db_path = Path(__file__).parent / "raven.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS threats;")
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
            alerted BOOLEAN
        );
    """)
    print("Table 'threats' created successfully.")

    cursor.execute("DROP TABLE IF EXISTS audit_results;")
    cursor.execute("""
        CREATE TABLE audit_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            check_name TEXT,
            status TEXT,
            detail TEXT,
            timestamp TEXT
        );
    """)
    print("Table 'audit_results' created successfully.")

    cursor.execute("DROP TABLE IF EXISTS honeypot_events;")
    cursor.execute("""
        CREATE TABLE honeypot_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            attacker_ip TEXT,
            port INTEGER,
            payload TEXT
        );
    """)
    print("Table 'honeypot_events' created successfully.")

    conn.commit()
    conn.close()
    print(f"Database initialized successfully at {db_path}")

if __name__ == "__main__":
    init_db()
