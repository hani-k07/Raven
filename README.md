# RAVEN 2.0: Autonomous Cybersecurity Monitoring & Defense System

![Build Status](https://img.shields.io/github/actions/workflow/tests.yml/hani-k07/Raven?branch=master)
![License](https://img.shields.io/github/license/hani-k07/Raven)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Last Commit](https://img.shields.io/github/last-commit/hani-k07/Raven)

RAVEN 2.0 is a professional-grade, autonomous SIEM (Security Information and Event Management) system designed to bridge the gap between raw system logs and actionable security intelligence. It transforms fragmented telemetry into high-fidelity threat alerts by combining active network deception, behavioral analysis, and Large Language Model (LLM) triage.

## Key Features

- **Real-Time Log Monitoring**: Proactive ingestion of Windows Event Logs and Linux `auth.log` to identify brute-force attacks and unauthorized access.
- **Active Honeypot Deception**: Deploys adaptive deception layers to ensnare reconnaissance attempts and identify attackers before they reach critical assets.
- **AI-Powered Threat Triage**: Integrates with OpenRouter for deep heuristic analysis of threats, featuring a seamless local **Ollama fallback** for air-gapped resilience.
- **Global IP Correlation**: Leverages the AbuseIPDB API to cross-reference attacker IPs against global reputation databases in real-time.
- **MITRE ATT&CK Mapping**: Every detected event is automatically mapped to specific MITRE tactics and techniques for standardized incident classification.
- **Multi-Channel Alerting**: Routes critical severity alerts immediately to security personnel via the Telegram Bot API to minimize dwell time.
- **Automated Forensic Reporting**: Generates professional PDF, CSV, and JSON dossiers for compliance audits and post-incident review.
- **File Integrity Monitoring (FIM)**: Tracks unauthorized changes to sensitive system files to detect persistence mechanisms and privilege escalation.

## Screenshots
The system provides a comprehensive SOC dashboard for real-time threat monitoring, including a live threat feed, security score tracking, and automated PDF report generation.

| Dashboard Overview | Threat Detail Analysis | Automated PDF Report |
| :---: | :---: | :---: |
| ![Dashboard](docs/screenshots/dashboard.png) | ![Threat Detail](docs/screenshots/threat-detail.png) | ![Report](docs/screenshots/report.png) |

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/hani-k07/Raven.git
cd Raven

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .\\.venv\\Scripts\\activate  # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
# Edit .env with your API keys (OpenRouter, AbuseIPDB, Telegram)

# 5. Launch the system
python run.py
```

## Tech Stack

- **Language**: Python 3.10+
- **GUI Framework**: CustomTkinter (Modern themed UI)
- **Data Storage**: SQLite3
- **AI/LLM**: OpenRouter API / Ollama (Local)
- **Security APIs**: AbuseIPDB, Telegram Bot API
- **Reporting**: ReportLab (PDF), Matplotlib (Visualizations)
- **System**: psutil, os, re, socket

## Data Integrity Guarantee

To ensure the credibility of its forensic output, RAVEN 2.0 implements a strict **Data Integrity Guarantee**. Every threat record in the database originates exclusively from the real-time detection pipeline:
- `log_parser.py` (Log telemetry)
- `honeypot.py` (Network deception)
- `fim.py` (File integrity)
- `process_monitor.py` (Behavioral anomalies)

**No manual threat injection paths exist in the production codebase.** This guarantee is programmatically enforced via a custom security check in the CI/CD pipeline that fails the build if any unauthorized `INSERT INTO threats` calls are detected outside these specific modules.

## Running Tests

```bash
# Run the full test suite
python -m pytest -v
```

---

## 📚 Technical Deep Dive

### Abstract
RAVEN 2.0 is a comprehensive, pure Python desktop application designed to provide holistic, real-time forensic monitoring and autonomous threat analysis. By integrating multi-layered log parsing, active deception environments (honeypots), and AI-driven telemetry evaluation, the system bridges the gap between raw alert generation and actionable intelligence. This project demonstrates the academic and practical efficacy of localized SIEM architectures coupled with Large Language Models (LLMs) for minimizing incident response times and establishing robust compliance postures.

### System Architecture

```text
                                  [ External Network ]
                                           │
 ┌─────────────────────────────────────────▼────────────────────────────────────────┐
 │                                 RAVEN 2.0 SYSTEM                                 │
 │                                                                                  │
 │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐               │
 │  │ Forensic Sentry │    │ Deception Grid  │    │ Compliance Bot  │               │
 │  │  (Log Poller)   │    │   (Honeypot)    │    │  (OS Auditor)   │               │
 │  └───────┬─────────┘    └───────┬─────────┘    └───────┬─────────┘               │
 │          │                      │                      │                         │
 │          └──────────────────────┼──────────────────────┘                         │
 │                                 ▼                                                │
 │                      ┌─────────────────────┐    ┌─────────────────────┐          │
 │                      │  Threat Analyzer    │───▶│   IP Reputation     │          │
 │                      │  (OpenRouter LLM)   │◀───│  (AbuseIPDB API)    │          │
 │                      └──────────┬──────────┘    └─────────────────────┘          │
 │                                 │                                                │
 │                                 ▼                                                │
 │                      ┌─────────────────────┐                                     │
 │                      │  Central SQLite DB  │                                     │
 │                      └────┬───────────┬────┘                                     │
 │                           │           │                                          │
 │                           ▼           ▼                                          │
 │           ┌─────────────────┐       ┌────────────────────────┐                   │
 │           │ Telegram Alerts │       │  Desktop Dashboard UI  │                   │
 │           └─────────────────┘       │  (CustomTkinter/Plots) │                   │
 │                                     └─────────┬──────────────┘                   │
 │                                               │                                  │
 │                                               ▼                                  │
 │                                     ┌──────────────────┐                         │
 │                                     │   PDF Reports    │                         │
 │                                     │   (ReportLab)    │                         │
 │                                     └──────────────────┘                         │
 └──────────────────────────────────────────────────────────────────────────────────┘
```

### Security Model

RAVEN 2.0 employs a Defense-in-Depth security model mapped linearly across four distinct operational layers:
- **Detection**: Proactively identifies anomalies via native OS log parsing (Windows Event Viewer / Linux `auth.log`) and active network deception (Honeypot ports) designed to ensnare reconnaissance attempts.
- **Analysis**: Routes parsed telemetry to an external LLM optimized for cybersecurity heuristics, simultaneously querying OSINT databases (AbuseIPDB) to ascertain the threat actor's global reputation and malicious intent.
- **Response**: Triggers immediate localized alerting mechanisms, mapping behaviors to the MITRE ATT&CK framework and routing critical severity alerts to security personnel via Telegram to minimize dwell time.
- **Reporting**: Compiles persistent telemetry and OS configuration audits into immutable SQLite storage, synthesizing automated PDF dossiers for compliance oversight and post-incident forensic review.

### MITRE ATT&CK Coverage

RAVEN 2.0 maps detected events directly to the global MITRE ATT&CK knowledge base.

| Event Type | Tactic | Technique ID | Technique Name |
|------------|--------|--------------|----------------|
| **SSH_BRUTE_FORCE** | Credential Access (TA0006) | T1110 | Brute Force |
| **PORT_SCAN** | Reconnaissance (TA0043) | T1046 | Network Service Discovery |
| **MALWARE_DOWNLOAD** | Execution (TA0002) | T1059 | Command & Scripting Interpreter |
| **PRIVILEGE_ESCALATION** | Privilege Escalation (TA0004) | T1548 | Abuse Elevation Control |
| **DATA_EXFILTRATION** | Exfiltration (TA0010) | T1041 | Exfiltration Over C2 Channel |
| **HONEYPOT** | Reconnaissance (TA0043) | T1595 | Active Scanning |
| **SUSPICIOUS_LOGIN** | Initial Access (TA0001) | T1078 | Valid Accounts |
| **HONEYPOT_TRIGGERED** | Reconnaissance (TA0043) | T1595 | Active Scanning |
| **FILE_INTEGRITY_CHANGE** | Persistence (TA0003) | T1565 | Data Manipulation |
| **UNEXPECTED_LISTENING_PORT** | Persistence (TA0003) | T1543 | Create or Modify System Process |
| **SUSPICIOUS_OUTBOUND_CONNECTION** | Exfiltration (TA0010) | T1041 | Exfiltration Over C2 Channel |
| **WIN_4648** | Lateral Movement (TA0008) | T1550 | Use Alternate Authentication Material |
| **WIN_4672** | Privilege Escalation (TA0004) | T1078.003 | Valid Accounts: Local Accounts |
| **WIN_4720** | Persistence (TA0003) | T1136 | Create Account |
| **SUSPICIOUS_WEB_REQUEST** | Initial Access (TA0001) | T1190 | Exploit Public-Facing Application |

### Threat Model

**What RAVEN Can Defend Against:**
- **Automated Reconnaissance**: Detects and logs port scans, vulnerability sweeps, and automated enumeration targeting exposed infrastructure.
- **Credential Stuffing & Brute Force**: Identifies repeated, rapid authentication failures against crucial protocols (SSH, Windows Logon).
- **Configuration Drift**: Detects when crucial OS defense mechanisms (Firewalls, Antivirus) are unexpectedly disabled or impaired.

**What RAVEN Cannot Defend Against (Out of Scope):**
- **Zero-Day Kernel Exploits**: RAVEN operates in user-space and lacks ring-0 visibility to detect sophisticated rootkits or memory-based exploits.
- **Encrypted Exfiltration at Scale**: Without SSL/TLS interception capabilities, RAVEN cannot inspect the payloads of encrypted outbound connections, only the volumetric metadata.
- **Inline Traffic Blocking**: As an out-of-band monitoring and alerting tool, RAVEN does not actively drop network packets (acting as an IDS, not an IPS).

### Academic References

1. [1] U. Tatar, "A Review of Security Information and Event Management (SIEM) Technologies," *IEEE Security & Privacy*, vol. 18, no. 6, pp. 44-51, Nov.-Dec. 2020.
2. [2] M. Nawrocki et al., "A Survey on Honeypots, Honeynets and Active Deception," *IEEE Communications Surveys & Tutorials*, vol. 22, no. 1, pp. 696-728, Firstquarter 2020.
3. [3] A. Buczak and E. Guven, "A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection," *IEEE Communications Surveys & Tutorials*, vol. 18, no. 2, pp. 1153-1176, Secondquarter 2016.
4. [4] B. Strom et al., "MITRE ATT&CK: Design and Philosophy," *The MITRE Corporation*, Technical Report, July 2018.
5. [5] G. O'Connor, "Python for Cybersecurity: Automation and Scripting for Defensive Operations," *IEEE International Conference on Cyber Security and Resilience (CSR)*, pp. 1-6, 2021.

### Ethics & Responsible Use

This tool was developed strictly for academic evaluation, defensive research, and internal network monitoring. **RAVEN 2.0 must only be deployed on infrastructure for which the operator has explicit, documented authorization.** The honeypot components are designed to observe, not to retaliate (hack-back), ensuring compliance with international cyber laws and responsible disclosure frameworks.
FIM TEST
TRIGGER_FIM
TRIGGER_FIM_2

FIM_TRIGGER_EVENT
FIM_TRIGGER_EVENT
TRIGGER
FIM_TRIGGER_FINAL
FIM_TRIGGER_FINAL