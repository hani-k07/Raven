import os
import sys
import re

# Authorized files that can insert into the threats table
AUTHORIZED_PATHS = {
    "log_parser.py",
    "fim.py",
    "honeypot.py",
    "process_monitor.py",
    "security_check.py",
}

# Patterns that indicate a manual threat injection
FORBIDDEN_PATTERN = r"INSERT INTO threats"

def check_security():
    violations = []
    for root, _, files in os.walk("."):
        if ".venv" in root or ".git" in root or ".claude" in root:
            continue

        for file in files:
            if not file.endswith(".py"):
                continue

            file_path = os.path.join(root, file)

            # Skip tests
            if "test_" in file or "_test" in file or "tests/" in file_path:
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if re.search(FORBIDDEN_PATTERN, content):
                        if file not in AUTHORIZED_PATHS:
                            violations.append(f"{file_path}: Found unauthorized 'INSERT INTO threats' pattern.")
            except Exception as e:
                print(f"Could not read {file_path}: {e}")

    if violations:
        print("[-] Security Check Failed: Unauthorized threat injection paths found!")
        for v in violations:
            print(v)
        sys.exit(1)
    else:
        print("[+] Security Check Passed: No unauthorized threat injection paths found.")
        sys.exit(0)

if __name__ == "__main__":
    check_security()
