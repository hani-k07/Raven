import os
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path

from config import validate_config, HONEYPOT_PORTS
import db_init
import auditor
from honeypot import start_honeypot
from log_parser import parse_logs
import app

# No logic changes here, just removing colorama init
# (Deleted line 15: init(autoreset=True))

ASCII_ART = r"""
------------------------------------------------------------
RAVEN 2.0 - Autonomous Cybersecurity Monitoring & Defense
------------------------------------------------------------
"""

def log_polling_daemon():
    """Polls logs every 60 seconds."""
    while True:
        try:
            print(f"[DAEMON] Running log parser...")
            parse_logs()
        except Exception as e:
            print(f"[ERROR] Log parser error: {e}")
        time.sleep(60)

def process_monitor_daemon():
    """Checks for process and network anomalies every 60 seconds."""
    import process_monitor
    while True:
        try:
            print(f"[DAEMON] Checking system anomalies...")
            process_monitor.monitor_system()
        except Exception as e:
            print(f"[ERROR] Process monitor error: {e}")
        time.sleep(60)

def report_scheduler_daemon():
    """Schedules and delivers automatic PDF reports."""
    from config import REPORT_SCHEDULE, REPORT_DELIVERY
    import report_generator
    import alerter

    if REPORT_SCHEDULE == "off":
        return

    while True:
        now = datetime.now()
        if REPORT_SCHEDULE == "daily":
            # Next midnight
            tomorrow = now + timedelta(days=1)
            next_run = tomorrow.replace(hour=0, minute=0, second=0, microsecond=0)
        elif REPORT_SCHEDULE == "weekly":
            # Next Monday midnight
            days_ahead = 0 - now.weekday() # Monday is 0
            if days_ahead <= 0: days_ahead += 7
            next_run = (now + timedelta(days=days_ahead)).replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            break

        sleep_seconds = (next_run - now).total_seconds()
        print(f"[SCHEDULER] Next report scheduled for {next_run} (in {sleep_seconds:.0f}s)")
        time.sleep(sleep_seconds)

        try:
            print(f"[SCHEDULER] Generating scheduled report...")
            out_dir = Path(__file__).parent / "reports"
            out_dir.mkdir(exist_ok=True)
            report_path = report_generator.generate_report(out_dir)

            # Delivery
            if REPORT_DELIVERY in ("email", "all"):
                alerter._send_email("RAVEN Scheduled Report", "Please find the attached security report.", str(report_path))
            if REPORT_DELIVERY in ("telegram", "all"):
                alerter._send_telegram_document("RAVEN Scheduled Security Report", str(report_path))

            print(f"[SUCCESS] Report delivered via {REPORT_DELIVERY}")
        except Exception as e:
            print(f"[ERROR] Scheduler error: {e}")

def main():
    print(ASCII_ART)
    print("Initializing RAVEN 2.0...\n")

    print("[1/6] Validating configuration...")
    try:
        validate_config()
    except Exception as e:
        print(f"Configuration Error: {e}")
        return

    # Check for Local LLM (Ollama) availability
    from config import OLLAMA_URL
    import requests
    try:
        # Ping the base host briefly (OLLama usually responds to / with 404 or similar,
        # but a connection is a good sign)
        from urllib.parse import urlparse
        parsed = urlparse(OLLAMA_URL)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        requests.get(base_url, timeout=2)
        print("[INFO] Local LLM fallback (Ollama) is available.")
    except Exception:
        print("[INFO] Local LLM fallback (Ollama) is offline or not configured.")

    print("[2/6] Initializing database...")
    db_init.init_db()

    print("[3/6] Running initial compliance audit...")
    try:
        auditor.run_audit()
    except Exception as e:
        print(f"Audit Error: {e}")
        
    print("[4/6] Starting Deception Grid (Honeypot)...")
    if HONEYPOT_PORTS:
        hp_thread = threading.Thread(target=start_honeypot, args=(HONEYPOT_PORTS,), daemon=True)
        hp_thread.start()
    else:
        print("No honeypot ports configured, skipping.")

    print("[5/6] Starting Forensic Sentry (Log Poller)...")
    log_thread = threading.Thread(target=log_polling_daemon, daemon=True)
    log_thread.start()

    print("[5.1/6] Starting System Anomaly Watchdog...")
    proc_thread = threading.Thread(target=process_monitor_daemon, daemon=True)
    proc_thread.start()

    print("[5.2/6] Starting Report Scheduler...")
    rep_thread = threading.Thread(target=report_scheduler_daemon, daemon=True)
    rep_thread.start()

    print("[6/6] Starting CustomTkinter Dashboard and Alert System...")
    app.run_app()

if __name__ == "__main__":
    main()
