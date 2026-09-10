
import alerter
import sqlite3
from unittest.mock import patch, MagicMock

def test_no_token():
    print("Testing: No token scenario...")
    with patch('alerter.TELEGRAM_BOT_TOKEN', None), \
         patch('alerter.TELEGRAM_CHAT_ID', None):
        try:
            res = alerter.check_and_alert()
            print(f"Result: {res}")
            assert res == 0
            print("Success: No token handled correctly.")
        except Exception as e:
            print(f"Failed: Threw exception {e}")

def test_digest_formatting():
    print("\nTesting: Digest formatting with 12 threats...")
    threats = []
    for i in range(5):
        threats.append({'source_ip': '1.1.1.1', 'event_type': 'Brute Force', 'severity': 'High', 'id': i})
    for i in range(5, 9):
        threats.append({'source_ip': '2.2.2.2', 'event_type': 'SQLi', 'severity': 'Critical', 'id': i})
    for i in range(9, 12):
        threats.append({'source_ip': '3.3.3.3', 'event_type': 'XSS', 'severity': 'High', 'id': i})

    messages = alerter._format_digest(threats)
    print(f"Number of messages: {len(messages)}")
    for i, msg in enumerate(messages):
        print(f"--- Message {i+1} ---\n{msg}\n--- End ---")
        assert len(msg) <= alerter.TELEGRAM_MSG_LIMIT

    full_text = "".join(messages)
    assert "High | Brute Force | 1.1.1.1 x5" in full_text
    assert "Critical | SQLi | 2.2.2.2 x4" in full_text
    assert "High | XSS | 3.3.3.3 x3" in full_text
    print("Success: Digest formatted correctly.")

if __name__ == "__main__":
    test_no_token()
    test_digest_formatting()
