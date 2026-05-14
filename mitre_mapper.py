MITRE_MAP = {
    "SSH_BRUTE_FORCE": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
    },
    "PORT_SCAN": {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
    },
    "MALWARE_DOWNLOAD": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command & Scripting Interpreter",
    },
    "PRIVILEGE_ESCALATION": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control",
    },
    "DATA_EXFILTRATION": {
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
    },
    "HONEYPOT": {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
    },
    "SUSPICIOUS_LOGIN": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    "HONEYPOT_TRIGGERED": {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
    },
}

def get_mitre(event_type: str) -> dict:
    """Returns MITRE ATT&CK mapping for a given event type, or Unknown fallback."""
    return MITRE_MAP.get(
        event_type,
        {
            "tactic_id": "Unknown",
            "tactic_name": "Unknown",
            "technique_id": "Unknown",
            "technique_name": "Unknown",
        },
    )
