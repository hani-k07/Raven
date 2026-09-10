from datetime import datetime, timedelta

def calculate_next_run(schedule):
    now = datetime.now()
    if schedule == "off":
        return "Off"

    if schedule == "daily":
        tomorrow = now + timedelta(days=1)
        return tomorrow.replace(hour=0, minute=0, second=0, microsecond=0)
    elif schedule == "weekly":
        days_ahead = 0 - now.weekday() # Monday is 0
        if days_ahead <= 0: days_ahead += 7
        return (now + timedelta(days=days_ahead)).replace(hour=0, minute=0, second=0, microsecond=0)
    return None

if __name__ == "__main__":
    print("Testing report schedule calculations...")

    # Test Daily
    next_daily = calculate_next_run("daily")
    print(f"Daily -> Next run: {next_daily}")
    assert next_daily.hour == 0 and next_daily.minute == 0

    # Test Weekly
    next_weekly = calculate_next_run("weekly")
    print(f"Weekly -> Next run: {next_weekly}")
    assert next_weekly.weekday() == 0 # Must be Monday
    assert next_weekly.hour == 0 and next_weekly.minute == 0

    print("\nSUCCESS: Schedule calculations are sane.")
