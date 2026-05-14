import os
from pathlib import Path
from dotenv import load_dotenv

env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
HONEYPOT_PORTS_STR = os.getenv("HONEYPOT_PORTS", "")
LOG_FILE_LINUX = os.getenv("LOG_FILE_LINUX")
LOG_FILE_WINDOWS = os.getenv("LOG_FILE_WINDOWS")
AI_MODEL = os.getenv("AI_MODEL", "nvidia/nemotron-3-8b-chat")
OPENROUTER_URL = os.getenv("OPENROUTER_URL", "https://openrouter.ai/api/v1/chat/completions")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

HONEYPOT_PORTS = [int(p.strip()) for p in HONEYPOT_PORTS_STR.split(",")] if HONEYPOT_PORTS_STR else []

def validate_config():
    """Validates that all required configuration variables are present."""
    required_keys = {
        "OPENROUTER_API_KEY": OPENROUTER_API_KEY,
    }

    missing_keys = [key for key, value in required_keys.items() if not value]

    if missing_keys:
        print(f"Warning: Missing required configuration keys: {', '.join(missing_keys)}")
        # We're just warning instead of crashing so the UI can still load
    else:
        print("Configuration validation successful. Core keys are present.")

if __name__ == "__main__":
    validate_config()
