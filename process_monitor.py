import psutil
import sqlite3
import requests
from datetime import datetime
from pathlib import Path
from analyzer import check_ip_reputation

# Use the same DB path as others
DB_PATH = Path(__file__).parent / "raven.db"

def get_listening_ports() -> list[dict]:
    """Lists all listening TCP/UDP ports and their associated process names."""
    listening = []
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == 'LISTEN':
                port = conn.laddr.port
                try:
                    process = psutil.Process(conn.pid)
                    name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    name = "Unknown"

                listening.append({
                    "port": port,
                    "process_name": name,
                    "ip": conn.laddr.ip
                })
    except (psutil.AccessDenied, Exception) as e:
        print(f"[ProcessMonitor] Error fetching connections: {e}")

    return listening

def check_for_new_ports() -> list[dict]:
    """Compares current listening ports against the baseline and reports anomalies."""
    current_ports = get_listening_ports()
    print(f"[Debug] Current ports: {len(current_ports)}")
    print(f"[Debug] DB Path: {DB_PATH}")
    anomalies = []

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    print(f"[Debug] Baseline count: {cursor.execute('SELECT count(*) FROM process_baseline').fetchone()[0]}")

    for p in current_ports:
        port = p["port"]
        process_name = p["process_name"]

        cursor.execute("SELECT process_name FROM process_baseline WHERE port = ?", (port,))
        row = cursor.fetchone()

        if not row:
            # New port discovered
            anomalies.append({
                "port": port,
                "process_name": process_name,
                "type": "UNEXPECTED_LISTENING_PORT",
                "severity": "Medium"
            })
            # Learn as we go: add to baseline
            cursor.execute(
                "INSERT INTO process_baseline (port, process_name, first_seen) VALUES (?, ?, ?)",
                (port, process_name, datetime.now().isoformat())
            )
        elif row[0] != process_name:
            # Port exists but process changed
            anomalies.append({
                "port": port,
                "process_name": process_name,
                "type": "UNEXPECTED_LISTENING_PORT",
                "severity": "Medium"
            })
            cursor.execute(
                "UPDATE process_baseline SET process_name = ?, first_seen = ? WHERE port = ?",
                (process_name, datetime.now().isoformat(), port)
            )

    conn.commit()
    conn.close()
    return anomalies

def check_outbound_reputation() -> list[dict]:
    """Checks established outbound connections for suspicious remote IPs."""
    anomalies = []
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip

                # Skip private ranges
                if any(remote_ip.startswith(pref) for pref in ("127.", "10.", "192.168.", "172.16.", "172.31.")):
                    continue

                reputation = check_ip_reputation(remote_ip)
                if reputation.get("abuse_score", 0) > 50:
                    anomalies.append({
                        "ip": remote_ip,
                        "abuse_score": reputation["abuse_score"],
                        "type": "SUSPICIOUS_OUTBOUND_CONNECTION",
                        "severity": "High"
                    })
    except (psutil.AccessDenied, Exception) as e:
        print(f"[ProcessMonitor] Error checking outbound: {e}")

    return anomalies

def monitor_system() -> None:
    """Main monitoring loop: checks ports and outbound connections, then injects threats."""
    timestamp = datetime.now().isoformat()

    # 1. Check for new ports
    new_ports = check_for_new_ports()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for anomaly in new_ports:
        raw_log = f"Unexpected listening port {anomaly['port']} used by {anomaly['process_name']}"
        # Use simple analysis since we don't have a complex log for this
        ai_analysis = {
            "severity": anomaly["severity"],
            "explanation": f"An unexpected process ({anomaly['process_name']}) is listening on port {anomaly['port']}.",
            "recommendation": "Verify if this process is authorized. Check for persistence mechanisms."
        }
        cursor.execute("""
            INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, "local", anomaly["type"], raw_log, anomaly["severity"],
              ai_analysis["explanation"], ai_analysis["recommendation"], 0))
        print(f"[ProcessMonitor] ALERT {anomaly['severity']} - {anomaly['type']} on port {anomaly['port']}")

    # 2. Check outbound connections
    outbound = check_outbound_reputation()
    for anomaly in outbound:
        raw_log = f"Suspicious outbound connection to {anomaly['ip']} (AbuseScore: {anomaly['abuse_score']})"
        ai_analysis = {
            "severity": anomaly["severity"],
            "explanation": f"Outgoing connection detected to known malicious IP {anomaly['ip']} with high abuse score.",
            "recommendation": "Isolate the host immediately. Investigate process initiating the connection."
        }
        cursor.execute("""
            INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, anomaly["ip"], anomaly["type"], raw_log, anomaly["severity"],
              ai_analysis["explanation"], ai_analysis["recommendation"], 0))
        print(f"[ProcessMonitor] 🚨 {anomaly['severity']} - {anomaly['type']} to {anomaly['ip']}")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    import db_init
    db_init.init_db()
    print("Running process monitor test...")
    print(f"Listening ports: {get_listening_ports()}")
    print(f"New ports: {check_for_new_ports()}")
    print(f"Outbound anomalies: {check_outbound_reputation()}")
