import os
import time
import threading
from pathlib import Path
from colorama import init, Fore

from config import validate_config, HONEYPOT_PORTS
import db_init
import auditor
from honeypot import start_honeypot
from log_parser import parse_logs
import app

init(autoreset=True)

ASCII_ART = f"""{Fore.RED}
  _____            __      __  ______   _   _   ___     ___  
 |  __ \           \ \    / / |  ____| | \ | | |__ \   / _ \ 
 | |__) |   __ _    \ \  / /  | |__    |  \| |    ) | | | | |
 |  _  /   / _` |    \ \/ /   |  __|   | . ` |   / /  | | | |
 | | \ \  | (_| |     \  /    | |____  | |\  |  / /_  | |_| |
 |_|  \_\  \__,_|      \/     |______| |_| \_| |____|  \___/ 
                                                             
    Cybersecurity Monitoring & Autonomous Defense System
{Fore.RESET}
"""

def log_polling_daemon():
    """Polls logs every 60 seconds."""
    while True:
        try:
            print(f"{Fore.CYAN}[DAEMON] Running log parser...")
            parse_logs()
        except Exception as e:
            print(f"{Fore.RED}[DAEMON] Log parser error: {e}")
        time.sleep(60)

def main():
    print(ASCII_ART)
    print(f"{Fore.YELLOW}Initializing RAVEN 2.0...\n")
    
    print(f"{Fore.GREEN}[1/6] Validating configuration...")
    try:
        validate_config()
    except Exception as e:
        print(f"{Fore.RED}Configuration Error: {e}")
        return
        
    print(f"{Fore.GREEN}[2/6] Initializing database...")
    db_init.init_db()
    
    print(f"{Fore.GREEN}[3/6] Running initial compliance audit...")
    try:
        auditor.run_audit()
    except Exception as e:
        print(f"{Fore.RED}Audit Error: {e}")
        
    print(f"{Fore.GREEN}[4/6] Starting Deception Grid (Honeypot)...")
    if HONEYPOT_PORTS:
        hp_thread = threading.Thread(target=start_honeypot, args=(HONEYPOT_PORTS,), daemon=True)
        hp_thread.start()
    else:
        print(f"{Fore.YELLOW}No honeypot ports configured, skipping.")
        
    print(f"{Fore.GREEN}[5/6] Starting Forensic Sentry (Log Poller)...")
    log_thread = threading.Thread(target=log_polling_daemon, daemon=True)
    log_thread.start()
    
    print(f"{Fore.GREEN}[6/6] Starting CustomTkinter Dashboard and Alert System...")
    app.run_app()

if __name__ == "__main__":
    main()
