import platform
import subprocess
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "raven.db"

def _run_cmd(cmd: str) -> str:
    """Runs a shell command and returns output or empty string."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception:
        return ""

def _audit_linux() -> list[dict]:
    """Runs compliance checks for Linux."""
    results = []
    
    ssh_out = _run_cmd("grep PermitRootLogin /etc/ssh/sshd_config")
    if "PermitRootLogin no" in ssh_out and not ssh_out.strip().startswith("#"):
        results.append({"check_name": "SSH Root Login", "status": "PASS", "detail": "Root login disabled"})
    else:
        results.append({"check_name": "SSH Root Login", "status": "FAIL", "detail": "Root login enabled or not explicitly disabled"})
        
    ufw_out = _run_cmd("ufw status")
    if "Status: active" in ufw_out:
        results.append({"check_name": "UFW Firewall", "status": "PASS", "detail": "UFW is active"})
    else:
        results.append({"check_name": "UFW Firewall", "status": "FAIL", "detail": "UFW is not active"})
        
    apt_out = _run_cmd("cat /etc/apt/apt.conf.d/20auto-upgrades")
    if "Unattended-Upgrade" in apt_out and "1" in apt_out:
        results.append({"check_name": "Auto Updates", "status": "PASS", "detail": "Unattended upgrades enabled"})
    else:
        results.append({"check_name": "Auto Updates", "status": "WARN", "detail": "Auto-upgrades not explicitly verified"})
        
    tmp_out = _run_cmd("find /tmp -type f -perm -0002")
    if not tmp_out:
        results.append({"check_name": "Tmp Permissions", "status": "PASS", "detail": "No world-writable files in /tmp"})
    else:
        results.append({"check_name": "Tmp Permissions", "status": "FAIL", "detail": "Found world-writable files in /tmp"})
        
    chage_out = _run_cmd("chage -l root")
    if "Maximum number of days between password change" in chage_out and ": 99999" not in chage_out:
        results.append({"check_name": "Password Aging", "status": "PASS", "detail": "Password aging configured for root"})
    else:
        results.append({"check_name": "Password Aging", "status": "FAIL", "detail": "No strict password aging for root"})
        
    return results

def _audit_windows() -> list[dict]:
    """Runs compliance checks for Windows."""
    results = []
    
    defend_out = _run_cmd("sc query WinDefend")
    if "RUNNING" in defend_out:
        results.append({"check_name": "Windows Defender", "status": "PASS", "detail": "WinDefend service is running"})
    else:
        results.append({"check_name": "Windows Defender", "status": "FAIL", "detail": "WinDefend service is not running"})
        
    fw_out = _run_cmd("netsh advfirewall show allprofiles")
    if "State" in fw_out and "ON" in fw_out:
        results.append({"check_name": "Windows Firewall", "status": "PASS", "detail": "Firewall active on at least one profile"})
    else:
        results.append({"check_name": "Windows Firewall", "status": "FAIL", "detail": "Firewall might be off"})
        
    uac_out = _run_cmd('reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA')
    if "0x1" in uac_out:
        results.append({"check_name": "UAC Enabled", "status": "PASS", "detail": "UAC is enabled"})
    else:
        results.append({"check_name": "UAC Enabled", "status": "FAIL", "detail": "UAC is disabled"})
        
    wu_out = _run_cmd('reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" /v NoAutoUpdate')
    if "0x0" in wu_out or "ERROR: The system was unable to find the specified registry key" in wu_out:
        results.append({"check_name": "Auto Updates", "status": "PASS", "detail": "Auto-updates not disabled by policy"})
    else:
        results.append({"check_name": "Auto Updates", "status": "WARN", "detail": "Auto-updates might be disabled"})
        
    return results

def run_audit() -> list[dict]:
    """Runs OS-appropriate compliance checks and stores results."""
    os_name = platform.system()
    results = []
    
    if os_name == "Linux":
        results = _audit_linux()
    elif os_name == "Windows":
        results = _audit_windows()
    else:
        print(f"Unsupported OS for auditing: {os_name}")
        return results
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()
    
    for r in results:
        cursor.execute("""
            INSERT INTO audit_results (check_name, status, detail, timestamp)
            VALUES (?, ?, ?, ?)
        """, (r['check_name'], r['status'], r['detail'], timestamp))
        
    conn.commit()
    conn.close()
    return results

if __name__ == "__main__":
    print("Testing standalone auditor.py...")
    audit_results = run_audit()
    print("-" * 60)
    print(f"{'CHECK NAME':<20} | {'STATUS':<6} | {'DETAIL'}")
    print("-" * 60)
    for res in audit_results:
        print(f"{res['check_name']:<20} | {res['status']:<6} | {res['detail']}")
    print("-" * 60)
