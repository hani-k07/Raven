import sqlite3
import threading
import requests
from pathlib import Path
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

DB_PATH = Path(__file__).parent / "raven.db"

# Track alert status silently to avoid console spam
_telegram_available = True
_telegram_fail_count = 0

def check_and_alert() -> int:
    """Checks the database for unalerted high/critical threats and sends Telegram alerts."""
    global _telegram_available, _telegram_fail_count
    
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return 0

    alerts_sent = 0
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, timestamp, source_ip, event_type, severity, ai_analysis, recommendation 
            FROM threats 
            WHERE alerted=0 AND severity IN ('High', 'Critical')
        """)
        
        threats = cursor.fetchall()
        
        for threat in threats:
            message = (
                f"🚨 RAVEN ALERT [{threat['severity']}]\n"
                f"Time: {threat['timestamp']}\n"
                f"Type: {threat['event_type']}\n"
                f"IP:   {threat['source_ip']}\n"
                f"Analysis: {threat['ai_analysis']}\n"
                f"Action: {threat['recommendation']}"
            )
            
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message
            }
            
            try:
                response = requests.post(url, json=payload, timeout=5)
                if response.status_code == 200:
                    cursor.execute("UPDATE threats SET alerted=1 WHERE id=?", (threat['id'],))
                    conn.commit()
                    alerts_sent += 1
                    _telegram_available = True
                    _telegram_fail_count = 0
                else:
                    # Mark as alerted anyway to prevent infinite retries
                    cursor.execute("UPDATE threats SET alerted=1 WHERE id=?", (threat['id'],))
                    conn.commit()
                    _telegram_fail_count += 1
                    if _telegram_fail_count <= 2:
                        print(f"[Alerter] Telegram error: {response.json().get('description', 'Unknown')}")
            except requests.exceptions.RequestException:
                # Network issue (timeout, blocked, etc.) - mark as alerted to prevent spam
                cursor.execute("UPDATE threats SET alerted=1 WHERE id=?", (threat['id'],))
                conn.commit()
                _telegram_fail_count += 1
                if _telegram_fail_count <= 2:
                    print("[Alerter] Telegram unreachable — alerts will be logged locally only.")
                _telegram_available = False
                    
    except Exception as e:
        pass  # Silently handle DB errors
    finally:
        if 'conn' in locals():
            conn.close()
            
    return alerts_sent

def is_telegram_connected() -> bool:
    """Returns whether Telegram is reachable."""
    return _telegram_available

def _daemon_loop() -> None:
    """Internal loop for the alert daemon."""
    check_and_alert()
    timer = threading.Timer(30.0, _daemon_loop)
    timer.daemon = True
    timer.start()

def start_alert_daemon() -> None:
    """Starts the background alert daemon."""
    _daemon_loop()

if __name__ == "__main__":
    start_alert_daemon()
    import time
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Daemon stopped.")
