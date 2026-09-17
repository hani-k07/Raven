import threading
import time
from config import HONEYPOT_PORTS
from honeypot import start_honeypot
from log_parser import parse_logs
import process_monitor
import fim

def log_daemon():
    while True:
        try:
            parse_logs()
        except Exception as e:
            print(f"Log error: {e}")
        time.sleep(30)

def proc_daemon():
    while True:
        try:
            process_monitor.monitor_system()
        except Exception as e:
            print(f"Proc error: {e}")
        time.sleep(30)

def fim_daemon():
    while True:
        try:
            fim.verify_integrity()
        except Exception as e:
            print(f"FIM error: {e}")
        time.sleep(30)

if __name__ == "__main__":
    print("Starting RAVEN Daemons...")

    # Initialize FIM baseline
    try:
        import fim
        fim.init_baseline()
        print("FIM baseline initialized.")
    except Exception as e:
        print(f"FIM init error: {e}")

    # Honeypot
    if HONEYPOT_PORTS:
        hp = threading.Thread(target=start_honeypot, args=(HONEYPOT_PORTS,), daemon=True)
        hp.start()
        print("Honeypot started.")

    # Log Parser
    lp = threading.Thread(target=log_daemon, daemon=True)
    lp.start()
    print("Log parser started.")

    # Process Monitor
    pm = threading.Thread(target=proc_daemon, daemon=True)
    pm.start()
    print("Process monitor started.")

    # FIM
    f = threading.Thread(target=fim_daemon, daemon=True)
    f.start()
    print("FIM started.")

    while True:
        time.sleep(1)
