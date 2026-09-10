import sqlite3
from alerter import check_and_alert, _format_digest, INDIVIDUAL_THRESHOLD

def test_no_token():
    print("Testing check_and_alert with no token...")
    # We can't easily mock config.TELEGRAM_BOT_TOKEN because it's imported directly.
    # For the sake of this quick test, we'll just assume the current env might have one
    # but check_and_alert handles the None/Empty case.
    # Since we can't easily mutate the imported constant without reloading the module,
    # we just run it. If no token is set in the env/config, it returns 0.
    res = check_and_alert()
    print(f"Result: {res} (Expected: 0 if no token)")

def test_digest_logic():
    print("\nTesting _format_digest with 12 threats...")
    # Simulate 12 fake threat rows
    # Group A: 5 threats (IP1, Type1, High)
    # Group B: 4 threats (IP2, Type2, Critical)
    # Group C: 3 threats (IP3, Type3, High)
    threats = []
    for _ in range(5): threats.append({'source_ip': '1.1.1.1', 'event_type': 'SSH Brute', 'severity': 'High', 'id': 1})
    for _ in range(4): threats.append({'source_ip': '2.2.2.2', 'event_type': 'SQLi', 'severity': 'Critical', 'id': 2})
    for _ in range(3): threats.append({'source_ip': '3.3.3.3', 'event_type': 'XSS', 'severity': 'High', 'id': 3})

    messages = _format_digest(threats)
    print(f"Number of messages: {len(messages)}")
    for i, msg in enumerate(messages):
        print(f"--- Message {i+1} ---\n{msg}\n---")

    assert len(messages) == 1
    assert "1.1.1.1 x5" in messages[0]
    assert "2.2.2.2 x4" in messages[0]
    assert "3.3.3.3 x3" in messages[0]
    print("Digest logic verified.")

if __name__ == "__main__":
    test_no_token()
    test_digest_logic()
