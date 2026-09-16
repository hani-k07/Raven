import os
import hashlib
import sqlite3
import platform
from datetime import datetime
from pathlib import Path
from config import FIM_PATHS
from analyzer import check_file_hash_reputation
import db_init

# Default watched paths if FIM_PATHS env is not set
DEFAULT_PATHS = {
    "Linux": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config",
        "/etc/sudoers",
        "/etc/crontab",
    ],
    "Windows": [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\config\\SECURITY",
    ],
}

WATCHED_PATHS = FIM_PATHS if FIM_PATHS else DEFAULT_PATHS.get(platform.system(), [])

def compute_hash(path: str) -> str | None:
    """Computes SHA-256 hash of a file. Returns None if unreadable."""
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, IOError):
        return None

def init_baseline() -> None:
    """Initializes the FIM baseline for all watched paths."""
    conn = sqlite3.connect(db_init.DB_PATH)
    cursor = conn.cursor()

    for path in WATCHED_PATHS:
        cursor.execute("SELECT hash FROM fim_baseline WHERE path = ?", (path,))
        if not cursor.fetchone():
            current_hash = compute_hash(path)
            if current_hash:
                cursor.execute(
                    "INSERT INTO fim_baseline (path, hash, last_checked) VALUES (?, ?, ?)",
                    (path, current_hash, datetime.now().isoformat())
                )

    conn.commit()
    conn.close()

def check_integrity() -> list[dict]:
    """Checks current hashes against the baseline and updates it."""
    results = []
    conn = sqlite3.connect(db_init.DB_PATH)
    cursor = conn.cursor()

    for path in WATCHED_PATHS:
        cursor.execute("SELECT hash FROM fim_baseline WHERE path = ?", (path,))
        row = cursor.fetchone()
        old_hash = row[0] if row else None
        new_hash = compute_hash(path)

        status = "OK"
        if new_hash is None:
            status = "MISSING" if old_hash else "OK"
        elif old_hash is None:
            status = "OK" # First time detection handled by init_baseline or dynamic add
        elif old_hash != new_hash:
            status = "CHANGED"

        if status != "OK":
            # Enrich with VirusTotal if changed
            vt_info = ""
            if status == "CHANGED" and new_hash:
                vt = check_file_hash_reputation(new_hash)
                if vt["verdict"] != "Unknown":
                    vt_info = f" | VT Verdict: {vt['verdict']} ({vt['malicious']}/{vt['total_engines']})"

            results.append({
                "path": path,
                "status": status,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "vt_info": vt_info
            })
            # Update baseline to avoid repeated alerts
            cursor.execute(
                "INSERT OR REPLACE INTO fim_baseline (path, hash, last_checked) VALUES (?, ?, ?)",
                (path, new_hash, datetime.now().isoformat())
            )

    conn.commit()
    conn.close()
    return results

def report_fim_change(change: dict) -> None:
    """Inserts a FIM change as a threat record."""
    path = change["path"]
    status = change["status"]
    vt_info = change.get("vt_info", "")
    raw_log = f"File {status}: {path}{vt_info}"

    conn = sqlite3.connect(db_init.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        "local",
        "FILE_INTEGRITY_CHANGE",
        raw_log,
        "High",
        f"File integrity violation detected on {path}. The file was {status.lower()}. {vt_info}",
        "Verify the change against authorized change management records. Check for unauthorized persistence.",
        False
    ))
    conn.commit()
    conn.close()
    print(f"[FIM] {status}: {path}")

if __name__ == "__main__":
    print("Testing FIM...")
    init_baseline()
    changes = check_integrity()
    print(f"Found {len(changes)} changes.")
