import platform
import re
import sqlite3
from pathlib import Path
from colorama import init, Fore
from config import LOG_FILE_LINUX, LOG_FILE_WINDOWS
from analyzer import analyze_threat
from datetime import datetime

init(autoreset=True)

DB_PATH = Path(__file__).parent / "raven.db"

def _insert_threat(timestamp: str, source_ip: str, event_type: str, raw_log: str, ai_analysis: dict) -> None:
    """Inserts a threat record into the database and prints to console."""
    severity = ai_analysis.get('severity', 'Medium')
    
    conn = sqlite3.connect(DB_PATH)
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
        ai_analysis.get('explanation', ''),
        ai_analysis.get('recommendation', ''),
        False
    ))
    conn.commit()
    conn.close()

    color_map = {
        "Critical": Fore.RED,
        "High": Fore.YELLOW,
        "Medium": Fore.CYAN,
        "Low": Fore.WHITE
    }
    color = color_map.get(severity, Fore.WHITE)
    print(f"{color}[{severity}] {event_type} from {source_ip}: {ai_analysis.get('explanation', '')}")

def _parse_linux_logs() -> list[dict]:
    """Parses Linux auth.log."""
    log_path = Path(LOG_FILE_LINUX)
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

def parse_logs() -> list[dict]:
    """Parses OS-specific logs and analyzes threats."""
    os_name = platform.system()
    results = []
    
    if os_name == "Linux":
        results = _parse_linux_logs()
    elif os_name == "Windows":
        results = _parse_windows_logs()
    else:
        print(f"Unsupported OS for log parsing: {os_name}")
        
    return results

if __name__ == "__main__":
    print("Testing standalone log_parser.py...")
    results = parse_logs()
    print(f"Parsed {len(results)} events.")
