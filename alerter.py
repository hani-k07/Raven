import sqlite3
import threading
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from pathlib import Path
from collections import Counter
import containment
from config import (
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
    SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL,
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD,
    ALERT_EMAIL_FROM, ALERT_EMAIL_TO
)
import db_init

# Burst protection constants
INDIVIDUAL_THRESHOLD = 3
DIGEST_MAX_GROUPS = 15
TELEGRAM_LIMIT = 4000
DISCORD_LIMIT = 2000

# Per-channel health tracking
CHANNEL_STATUS = {
    "Telegram": {"available": True, "fail_count": 0},
    "Slack": {"available": True, "fail_count": 0},
    "Discord": {"available": True, "fail_count": 0},
    "Email": {"available": True, "fail_count": 0},
}

def _chunk_text(text: str, limit: int) -> list[str]:
    """Splits text into chunks of maximum size."""
    chunks = []
    while len(text) > limit:
        chunks.append(text[:limit])
        text = text[limit:]
    chunks.append(text)
    return chunks

def _send_telegram(text: str) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID: return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text}
    try:
        resp = requests.post(url, json=payload, timeout=5)
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False

def _send_slack(text: str) -> bool:
    if not SLACK_WEBHOOK_URL: return False
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=5)
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False

def _send_discord(text: str) -> bool:
    if not DISCORD_WEBHOOK_URL: return False
    try:
        resp = requests.post(DISCORD_WEBHOOK_URL, json={"content": text}, timeout=5)
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False

def _send_email(subject: str, text: str, attachment_path: str = None) -> bool:
    if not SMTP_HOST: return False
    try:
        if attachment_path:
            msg = MIMEMultipart()
            msg.attach(MIMEText(text))
            with open(attachment_path, "rb") as f:
                part = MIMEApplication(f.read(), Name=Path(attachment_path).name)
                part['Content-Disposition'] = f'attachment; filename="{Path(attachment_path).name}"'
                msg.attach(part)
        else:
            msg = MIMEText(text)

        msg["Subject"] = subject
        msg["From"] = ALERT_EMAIL_FROM or "raven@soc.local"
        msg["To"] = ALERT_EMAIL_TO or "admin@soc.local"

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT or 587, timeout=5) as server:
            if SMTP_USER and SMTP_PASSWORD:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception:
        return False

def _send_telegram_document(caption: str, file_path: str) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID: return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    try:
        with open(file_path, 'rb') as f:
            files = {'document': f}
            payload = {"chat_id": TELEGRAM_CHAT_ID, "caption": caption}
            resp = requests.post(url, data=payload, files=files, timeout=10)
            return resp.status_code == 200
    except Exception:
        return False

def _format_single(threat) -> str:
    return (
        f"RAVEN ALERT [{threat['severity']}]\n"
        f"Time: {threat['timestamp']}\n"
        f"Type: {threat['event_type']}\n"
        f"IP:   {threat['source_ip']}\n"
        f"Analysis: {threat['ai_analysis']}\n"
        f"Recommended action: {threat['recommendation']}"
    )

def _format_digest(threats) -> list[str]:
    counts = Counter((t['source_ip'], t['event_type'], t['severity']) for t in threats)
    sorted_groups = counts.most_common()
    top_groups = sorted_groups[:DIGEST_MAX_GROUPS]
    remaining = len(sorted_groups) - DIGEST_MAX_GROUPS

    lines = ["RAVEN BURST DIGEST"]
    for (ip, etype, sev), count in top_groups:
        suffix = f" x{count}" if count > 1 else ""
        lines.append(f"- {sev} | {etype} | {ip}{suffix}")
    if remaining > 0:
        lines.append(f"...and {remaining} more source(s) not shown")

    full_text = "\n".join(lines)
    return [full_text]

def check_and_alert() -> int:
    """Checks for unalerted threats and attempts multi-channel delivery."""
    senders = {
        "Telegram": lambda text: _send_telegram(text),
        "Slack": lambda text: _send_slack(text),
        "Discord": lambda text: _send_discord(text),
        "Email": lambda text: _send_email("RAVEN Security Alert", text),
    }

    alerts_sent = 0
    try:
        conn = sqlite3.connect(db_init.DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, timestamp, source_ip, event_type, severity, ai_analysis, recommendation
            FROM threats
            WHERE alerted=0 AND severity IN ('High', 'Critical')
        """)

        threats = cursor.fetchall()
        if not threats:
            return 0

        if len(threats) <= INDIVIDUAL_THRESHOLD:
            for threat in threats:
                msg = _format_single(threat)
                success = False
                for name, sender in senders.items():
                    if (name == "Telegram" and (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)) or \
                       (name == "Slack" and SLACK_WEBHOOK_URL) or \
                       (name == "Discord" and DISCORD_WEBHOOK_URL) or \
                       (name == "Email" and SMTP_HOST):
                        if sender(msg):
                            success = True
                            CHANNEL_STATUS[name]["available"] = True
                            CHANNEL_STATUS[name]["fail_count"] = 0
                        else:
                            CHANNEL_STATUS[name]["available"] = False
                            CHANNEL_STATUS[name]["fail_count"] += 1

                if success:
                    alerts_sent += 1
                    # Auto-containment for high-severity alerts
                    contained = containment.auto_contain({
                        "severity": threat['severity'],
                        "event_type": threat['event_type'],
                        "source_ip": threat['source_ip']
                    })
                    if contained:
                        print(f"  {_RED}[CONTAINMENT]{_RST} Automatically blocked {threat['source_ip']}")
                cursor.execute("UPDATE threats SET alerted=1 WHERE id=?", (threat['id'],))
        else:
            digests = _format_digest(threats)
            for digest in digests:
                for name, sender in senders.items():
                    if (name == "Telegram" and (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)) or \
                       (name == "Slack" and SLACK_WEBHOOK_URL) or \
                       (name == "Discord" and DISCORD_WEBHOOK_URL) or \
                       (name == "Email" and SMTP_HOST):

                        limit = TELEGRAM_LIMIT if name == "Telegram" else (DISCORD_LIMIT if name == "Discord" else 10000)
                        chunks = _chunk_text(digest, limit)
                        for chunk in chunks:
                            if sender(chunk):
                                alerts_sent += 1
                                CHANNEL_STATUS[name]["available"] = True
                                CHANNEL_STATUS[name]["fail_count"] = 0
                            else:
                                CHANNEL_STATUS[name]["available"] = False
                                CHANNEL_STATUS[name]["fail_count"] += 1

                # Auto-contain high-risk IPs from the burst
                for threat in threats:
                    containment.auto_contain({
                        "severity": threat['severity'],
                        "event_type": threat['event_type'],
                        "source_ip": threat['source_ip']
                    })

                ids = [t['id'] for t in threats]

            ids = [t['id'] for t in threats]
            cursor.execute(f"UPDATE threats SET alerted=1 WHERE id IN ({','.join(['?']*len(ids))})", ids)

        conn.commit()
    except Exception as e:
        print(f"[Alerter] Critical error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

    return alerts_sent

def get_channel_status() -> dict:
    """Returns connectivity status for all configured channels."""
    return CHANNEL_STATUS

def is_telegram_connected() -> bool:
    """Checks if Telegram is configured and available."""
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID and CHANNEL_STATUS["Telegram"]["available"])

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
