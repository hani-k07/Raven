# RAVEN 2.0
Cybersecurity Monitoring & Autonomous Defense System.

RAVEN 2.0 integrates log parsing (Forensic Sentry), a honeypot (Deception Grid), an OS auditor (Compliance Bot), and an AI Threat Analyzer (OpenRouter) into a unified Flask dashboard. It also features real-time Telegram alerts and automated PDF reporting.

## Architecture Diagram
```text
  [Logs] ----> (Forensic Sentry) ---+     +--> (AI Threat Analyzer)
                                    |     |
  [Ports] ---> (Deception Grid) ----+---> [SQLite Database] ---> [Flask Dashboard]
                                    |            |
  [OS Config]->(Compliance Bot) ----+            +--> (Telegram Alerter)
                                                 |
                                                 +--> (PDF Report Generator)
```

## Quick Start
1. **Clone the repository:**
   `git clone <your-repo-url>`
2. **Install dependencies:**
   `pip install -r requirements.txt`
3. **Set up the environment:**
   Copy `.env.example` to `.env` and fill in your actual values.
4. **Launch RAVEN 2.0:**
   `python run.py`
5. **Open the Dashboard:**
   Navigate to `http://localhost:5000` in your web browser.

## .env Setup Guide
- `OPENROUTER_API_KEY`: Your API key from OpenRouter for AI analysis.
- `TELEGRAM_BOT_TOKEN`: The bot token provided by BotFather on Telegram.
- `TELEGRAM_CHAT_ID`: Your personal Telegram Chat ID to receive alerts.
- `FLASK_SECRET_KEY`: A random string to secure Flask sessions.
- `HONEYPOT_PORTS`: Comma-separated list of ports to listen on (e.g., 2222,2121,2323).
- `LOG_FILE_LINUX`: Path to the log file on Linux (e.g., `/var/log/auth.log`).
- `LOG_FILE_WINDOWS`: Path to Windows Event Logs or empty.
- `AI_MODEL`: Model name (default: `nvidia/nemotron-3-8b-chat`).
- `OPENROUTER_URL`: Endpoint URL (default: `https://openrouter.ai/api/v1/chat/completions`).

## Demo Day Script
Run this script to show off RAVEN 2.0 without a live attack vector.
1. Start RAVEN in terminal 1: `python run.py`
2. Open the dashboard at `http://localhost:5000`
3. Open a second terminal and run: `python demo_sim.py`
4. **Step 1 (0s):** Watch the dashboard's total threats increase. A Honeypot hit is recorded.
5. **Step 2 (10s later):** Wait 10 seconds. 20 Critical SSH Brute Force events will flood the database. 
6. Watch your phone! A real Telegram alert will trigger due to the unalerted critical threats.
7. **Step 3 (25s later):** An OS Compliance Audit failure is injected. Notice the Security Score drop on the dashboard dynamically.
8. Click the **"Generate PDF Report"** button to export the entire simulated attack and compliance failure as a professional report.

## Troubleshooting
1. **Configuration Error on Startup**
   - *Fix:* Ensure `.env` is copied from `.env.example` and all required keys are filled out.
2. **Telegram Alerts Not Arriving**
   - *Fix:* Verify `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are correct. Start a chat with the bot first so it has permission to message you.
3. **Database Locked Error**
   - *Fix:* Stop the app completely and restart. Ensure no other scripts are holding the SQLite database open.
4. **pywin32 ImportError on Windows**
   - *Fix:* Install it manually using `pip install pywin32` or run as administrator if parsing Windows Security Event logs.
5. **Port Binding Errors (Honeypot)**
   - *Fix:* Ensure the ports specified in `HONEYPOT_PORTS` are not being used by other services (like an actual SSH server on port 2222).
