import platform
import re
import sqlite3
from pathlib import Path
import config
from analyzer import analyze_threat
from datetime import datetime
import honeypot
import db_init

def _is_ip_allowlisted(ip: str) -> bool:
    """Checks if an IP is in the allowlist."""
    conn = sqlite3.connect(db_init.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM ip_allowlist WHERE ip = ?", (ip,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def _insert_threat(timestamp: str, source_ip: str, event_type: str, raw_log: str, ai_analysis: dict) -> None:
    """Inserts a threat record into the database and prints to console."""
    severity = ai_analysis.get('severity', 'Medium')
    explanation = ai_analysis.get('explanation', '')
    recommendation = ai_analysis.get('recommendation', '')

    if _is_ip_allowlisted(source_ip):
        severity = "Low"
        explanation = f"[ALLOWLISTED] {explanation}"

    conn = sqlite3.connect(db_init.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        source_ip,
        event_type,
        raw_log,
        severity,
        explanation,
        recommendation,
        False
    ))
    conn.commit()
    conn.close()

    print(f"[{severity}] {event_type} from {source_ip}: {ai_analysis.get('explanation', '')}")

def _parse_linux_logs() -> list[dict]:
    """Parses Linux auth.log."""
    log_path = Path(config.LOG_FILE_LINUX)
    if not log_path.exists():
        print(f"Log file not found: {log_path}")
        return []
        
    patterns = {
        "Failed SSH": r"Failed password for .* from (\S+)",
        "Invalid user": r"Invalid user .* from (\S+)",
        "Root login refused": r"ROOT LOGIN REFUSED from (\S+)"
    }
    
    processed = 0
    threats_found = []
    
    try:
        with open(log_path, 'r') as f:
            lines = f.readlines()
            for line in lines[-1000:]:
                if processed >= 50:
                    break
                    
                for event_type, pattern in patterns.items():
                    match = re.search(pattern, line)
                    if match:
                        source_ip = match.group(1)
                        analysis = analyze_threat(event_type, line.strip(), source_ip)
                        timestamp = datetime.now().isoformat()
                        
                        _insert_threat(timestamp, source_ip, event_type, line.strip(), analysis)
                        threats_found.append({
                            "event_type": event_type,
                            "source_ip": source_ip,
                            "raw_log": line.strip(),
                            "analysis": analysis
                        })
                        processed += 1
                        break
    except Exception as e:
        print(f"Error reading Linux logs: {e}")
        
    return threats_found

def _parse_windows_logs() -> list[dict]:
    """Parses Windows Security Event Log using win32evtlog."""
    threats_found = []
    processed = 0
    
    try:
        import win32evtlog
        import win32evtlogutil
        
        server = 'localhost'
        logtype = 'Security'
        
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        
        while events and processed < 50:
            for event in events:
                if processed >= 50:
                    break
                    
                if event.EventID == 4625:
                    data = event.StringInserts
                    source_ip = data[19] if data and len(data) > 19 else "Unknown"
                    raw_log = f"Failed logon. Target: {data[5] if data and len(data) > 5 else 'Unknown'}"
                    event_type = "Failed Logon"
                elif event.EventID == 4648:
                    data = event.StringInserts
                    source_ip = data[1] if data and len(data) > 1 else "Unknown"
                    raw_log = f"Explicit credentials used. Target: {data[2] if data and len(data) > 2 else 'Unknown'}"
                    event_type = "WIN_4648"
                elif event.EventID == 4672:
                    data = event.StringInserts
                    source_ip = "local"
                    raw_log = f"Special privileges assigned to: {data[1] if data and len(data) > 1 else 'Unknown'}"
                    event_type = "WIN_4672"
                elif event.EventID == 4720:
                    data = event.StringInserts
                    source_ip = "local"
                    raw_log = f"New user account created: {data[0] if data and len(data) > 0 else 'Unknown'}"
                    event_type = "WIN_4720"
                else:
                    continue

                    analysis = analyze_threat(event_type, raw_log, source_ip)
                    timestamp = event.TimeGenerated.Format() if event.TimeGenerated else datetime.now().isoformat()
                    
                    _insert_threat(timestamp, source_ip, event_type, raw_log, analysis)
                    threats_found.append({
                        "event_type": event_type,
                        "source_ip": source_ip,
                        "raw_log": raw_log,
                        "analysis": analysis
                    })
                    processed += 1
                    
            if processed < 50:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
    except ImportError:
        print("pywin32 is not installed. Required for Windows event log parsing.")
    except Exception as e:
        print(f"Error reading Windows logs: {e}")
        
    return threats_found

def _parse_web_server_logs(log_path: str) -> list[dict]:
    """Parses Nginx/Apache combined log format."""
    path = Path(log_path)
    if not path.exists():
        return []

    # Combined Log Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
    # Example: 127.0.0.1 - - [10/Sep/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123 "-" "Mozilla/5.0"
    pattern = r'^(\S+) \S+ \S+ \[(.*?)\] "(.*?) (.*?) .*?" (\d{3}) \d+ ".*?" "(.*?)"'

    threats_found = []
    processed = 0

    try:
        with open(path, 'r') as f:
            lines = f.readlines()
            for line in lines[-1000:]:
                if processed >= 50:
                    break

                match = re.search(pattern, line)
                if match:
                    ip, ts, method, path_req, status, ua = match.groups()
                    status_int = int(status)

                    is_suspicious = False
                    if any(p in path_req.lower() for p in honeypot.SENSITIVE_PATHS):
                        is_suspicious = True
                    elif status_int >= 400:
                        # For simplicity, flag as suspicious if 4xx/5xx
                        is_suspicious = True

                    if is_suspicious:
                        event_type = "SUSPICIOUS_WEB_REQUEST"
                        raw_log = f"Web request: {method} {path_req} returned {status} from {ip} (UA: {ua})"
                        analysis = analyze_threat(event_type, raw_log, ip)
                        _insert_threat(datetime.now().isoformat(), ip, event_type, raw_log, analysis)
                        threats_found.append({
                            "event_type": event_type,
                            "source_ip": ip,
                            "raw_log": raw_log,
                            "analysis": analysis
                        })
                        processed += 1
    except Exception as e:
        print(f"Error reading web logs: {e}")

    return threats_found

def parse_logs() -> list[dict]:
    """Parses OS-specific logs and analyzes threats."""
    os_name = platform.system()
    results = []

    if os_name == "Linux":
        results.extend(_parse_linux_logs())
    elif os_name == "Windows":
        results.extend(_parse_windows_logs())
    else:
        print(f"Unsupported OS for log parsing: {os_name}")

    if config.WEB_LOG_PATH:
        results.extend(_parse_web_server_logs(config.WEB_LOG_PATH))

    return results

if __name__ == "__main__":
    print("Testing standalone log_parser.py...")
    results = parse_logs()
    print(f"Parsed {len(results)} events.")
