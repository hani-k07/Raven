# RAVEN 2.0: Autonomous Cybersecurity Monitoring & Defense System

## 1. Abstract
RAVEN 2.0 is a comprehensive, pure Python desktop application designed to provide holistic, real-time forensic monitoring and autonomous threat analysis. By integrating multi-layered log parsing, active deception environments (honeypots), and AI-driven telemetry evaluation, the system bridges the gap between raw alert generation and actionable intelligence. This project demonstrates the academic and practical efficacy of localized SIEM architectures coupled with Large Language Models (LLMs) for minimizing incident response times and establishing robust compliance postures.

## 2. System Architecture

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

## 3. Security Model

RAVEN 2.0 employs a Defense-in-Depth security model mapped linearly across four distinct operational layers:
- **Detection**: Proactively identifies anomalies via native OS log parsing (Windows Event Viewer / Linux `auth.log`) and active network deception (Honeypot ports) designed to ensnare reconnaissance attempts.
- **Analysis**: Routes parsed telemetry to an external LLM optimized for cybersecurity heuristics, simultaneously querying OSINT databases (AbuseIPDB) to ascertain the threat actor's global reputation and malicious intent.
- **Response**: Triggers immediate localized alerting mechanisms, mapping behaviors to the MITRE ATT&CK framework and routing critical severity alerts to security personnel via Telegram to minimize dwell time.
- **Reporting**: Compiles persistent telemetry and OS configuration audits into immutable SQLite storage, synthesizing automated PDF dossiers for compliance oversight and post-incident forensic review.

## 4. MITRE ATT&CK Coverage

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

## 5. Threat Model

**What RAVEN Can Defend Against:**
- **Automated Reconnaissance**: Detects and logs port scans, vulnerability sweeps, and automated enumeration targeting exposed infrastructure.
- **Credential Stuffing & Brute Force**: Identifies repeated, rapid authentication failures against crucial protocols (SSH, Windows Logon).
- **Configuration Drift**: Detects when crucial OS defense mechanisms (Firewalls, Antivirus) are unexpectedly disabled or impaired.

**What RAVEN Cannot Defend Against (Out of Scope):**
- **Zero-Day Kernel Exploits**: RAVEN operates in user-space and lacks ring-0 visibility to detect sophisticated rootkits or memory-based exploits.
- **Encrypted Exfiltration at Scale**: Without SSL/TLS interception capabilities, RAVEN cannot inspect the payloads of encrypted outbound connections, only the volumetric metadata.
- **Inline Traffic Blocking**: As an out-of-band monitoring and alerting tool, RAVEN does not actively drop network packets (acting as an IDS, not an IPS).

## 6. Academic References

1. [1] U. Tatar, "A Review of Security Information and Event Management (SIEM) Technologies," *IEEE Security & Privacy*, vol. 18, no. 6, pp. 44-51, Nov.-Dec. 2020.
2. [2] M. Nawrocki et al., "A Survey on Honeypots, Honeynets and Active Deception," *IEEE Communications Surveys & Tutorials*, vol. 22, no. 1, pp. 696-728, Firstquarter 2020.
3. [3] A. Buczak and E. Guven, "A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection," *IEEE Communications Surveys & Tutorials*, vol. 18, no. 2, pp. 1153-1176, Secondquarter 2016.
4. [4] B. Strom et al., "MITRE ATT&CK: Design and Philosophy," *The MITRE Corporation*, Technical Report, July 2018.
5. [5] G. O'Connor, "Python for Cybersecurity: Automation and Scripting for Defensive Operations," *IEEE International Conference on Cyber Security and Resilience (CSR)*, pp. 1-6, 2021.

## 7. Limitations & Future Work

While RAVEN 2.0 establishes a robust foundation for active monitoring, several limitations present opportunities for future research:
- **API Latency Dependency**: The threat analysis pipeline relies on external HTTP requests to OpenRouter and AbuseIPDB. High network latency or API outages cause temporary degradation of analytic fidelity, forcing the system into a static fallback mode. Future iterations should explore quantized, locally-hosted LLMs (e.g., Llama.cpp) to ensure air-gapped resilience.
- **Log Source Constraints**: The current log parser is tightly coupled to specific OS files (e.g., `/var/log/auth.log`). Expanding ingestion to process structured network flow logs (Zeek/Suricata) via sys-log would exponentially increase visibility.
- **Static Compliance Checks**: The auditor module utilizes static rule-sets rather than dynamic behavioral baselines. Integrating machine-learning anomaly detection for process monitoring could provide a more adaptive compliance posture.

## 8. Ethics & Responsible Use

This tool was developed strictly for academic evaluation, defensive research, and internal network monitoring. **RAVEN 2.0 must only be deployed on infrastructure for which the operator has explicit, documented authorization.** The honeypot components are designed to observe, not to retaliate (hack-back), ensuring compliance with international cyber laws and responsible disclosure frameworks.

---

## Quick Start
```bash
pip install -r requirements.txt
# Copy .env.example to .env and fill in your API keys
python run.py
```

## Configuration (.env)
| Variable | Description |
|----------|-------------|
| `OPENROUTER_API_KEY` | API key from openrouter.ai |
| `ABUSEIPDB_API_KEY` | API key from AbuseIPDB |
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Your Telegram Chat ID |
| `HONEYPOT_PORTS` | Comma-separated ports (e.g., `2222,2121`) |
| `AI_MODEL` | AI model name (default: `nvidia/nemotron-3-8b-chat`) |

## Testing
```bash
# Terminal 1: Start RAVEN
python run.py

# Terminal 2: Run the attack simulator
python demo_sim.py
```
