# RAVEN 2.0
**Cybersecurity Monitoring & Autonomous Defense System**

A pure Python desktop application that integrates forensic log parsing, honeypot deception, OS compliance auditing, AI-powered threat analysis, real-time Telegram alerts, and professional PDF reporting into a single unified dashboard.

## Quick Start
```bash
pip install -r requirements.txt
# Copy .env.example to .env and fill in your API keys
python run.py
```

## Architecture
```
[System Logs] → Forensic Sentry ──┐
[Open Ports]  → Deception Grid ───┤→ AI Analyzer → SQLite DB → Desktop Dashboard
[OS Config]   → Compliance Bot ───┘                    │
                                              ┌────────┴────────┐
                                         Telegram Alerts    PDF Reports
```

## Configuration (.env)
| Variable | Description |
|----------|-------------|
| `OPENROUTER_API_KEY` | API key from openrouter.ai |
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Your Telegram Chat ID |
| `HONEYPOT_PORTS` | Comma-separated ports (e.g., `2222,2121`) |
| `AI_MODEL` | AI model name (default: `nvidia/nemotron-3-8b-chat`) |

## Testing
```bash
# Terminal 1: Start RAVEN
python run.py

# Terminal 2: Run the attack simulator
python demo_sim.py
```

## Tech Stack
Python 3.10+ · CustomTkinter · SQLite · OpenRouter API · Telegram Bot API · ReportLab
