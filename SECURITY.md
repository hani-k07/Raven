# Security & Data Integrity Policy

## Data Integrity Guarantee
RAVEN 2.0 is designed as a high-fidelity defensive tool. To maintain the trustworthiness of its telemetry and forensic reports, the system adheres to a strict **Data Integrity Guarantee**:

**All entries in the `threats` database table must originate from real detection telemetry.**

Manual injection of threats via the UI, seed scripts, or administrative overrides is strictly prohibited in production environments. This ensures that the Security Score and AI Analysis are based on actual observed behaviors, not synthetic data.

## Authorized Detection Paths
Only the following modules are authorized to write to the `threats` table:
- `log_parser.py`: Forensic log analysis.
- `fim.py`: File Integrity Monitoring.
- `honeypot.py`: Deception grid events.
- `process_monitor.py`: Network and process anomaly detection.

## Integrity Enforcement
The project includes a security check (`security_check.py`) to be integrated into CI/CD pipelines. This check scans the codebase for unauthorized database write patterns to prevent the re-introduction of "demo" or "simulation" paths.

## Real Pipeline Testing Guide
Since manual injection is disabled, validation must be performed by triggering the actual detection pipeline:

### 1. Testing the Deception Grid (Honeypots)
Attempt to connect to the configured honeypot ports from an external machine:
```bash
nmap -p 2222,2121 <raven-host-ip>
```
Or use `nc` (netcat):
```bash
nc -zv <raven-host-ip> 2222
```

### 2. Testing File Integrity Monitoring (FIM)
Modify one of the paths listed in `config.FIM_PATHS` (e.g., `/etc/passwd` on Linux or a monitored system file on Windows).

### 3. Testing Process Monitoring
Start a new service that listens on a non-standard port (e.g., using Python's `http.server`):
```bash
python -m http.server 8888
```

### 4. Testing Log Parsing
Manually append a failed login attempt to the monitored log file (e.g., `auth.log`):
```bash
echo "Sep 10 10:00:00 host sshd[123]: Failed password for root from 1.2.3.4 port 5678 ssh2" >> /var/log/auth.log
```

## Hardening Process
The system has undergone a hardening process to transition from a PoC to a production-ready tool:
- Removed `demo_sim.py` and all synthetic attack generators.
- Excised all UI-based threat injection buttons.
- Purged all seed/sample data.
- Established a strict "Real Pipeline" testing workflow.
