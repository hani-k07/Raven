import sqlite3
import threading
import requests
from pathlib import Path
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

DB_PATH = Path(__file__).parent / "raven.db"

def check_and_alert() -> int:
    """Checks the database for unalerted high/critical threats and sends Telegram alerts."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram credentials missing. Alerts will not be sent.")
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
            
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                cursor.execute("UPDATE threats SET alerted=1 WHERE id=?", (threat['id'],))
                conn.commit()
                alerts_sent += 1
            else:
                print(f"Failed to send Telegram alert for threat ID {threat['id']}: {response.text}")
                
    except Exception as e:
        print(f"Error in check_and_alert: {e}")
    finally:
        if 'conn' in locals():
            conn.close()
            
    return alerts_sent

def _daemon_loop() -> None:
    """Internal loop for the alert daemon."""
    check_and_alert()
    timer = threading.Timer(30.0, _daemon_loop)
    timer.daemon = True
    timer.start()

def start_alert_daemon() -> None:
    """Starts the background alert daemon."""
    print("Alert daemon started — polling every 30s")
    _daemon_loop()

if __name__ == "__main__":
    start_alert_daemon()
    import time
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Daemon stopped.")
