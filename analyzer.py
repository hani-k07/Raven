import json
import re
import requests
from config import (
    OPENROUTER_API_KEY, AI_MODEL, OPENROUTER_URL,
    ABUSEIPDB_API_KEY, OLLAMA_URL, OLLAMA_MODEL,
    VIRUSTOTAL_API_KEY, SHODAN_API_KEY
)

_VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}

def _extract_json(text: str) -> dict | None:
    """Tries multiple strategies to extract a JSON object from a model response."""
    # Strip markdown code fences
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    # Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Find first {...} block via regex
    match = re.search(r"\{.*?\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return None


def _analyze_with_ollama(event_type: str, raw_log: str, source_ip: str) -> dict | None:
    """Attempts to analyze a threat using a local Ollama instance."""
    prompt = (
        f"You are a cybersecurity analyst. Analyze this security event.\n"
        f"Event type: {event_type}\n"
        f"Raw log: {raw_log}\n"
        f"Source IP: {source_ip}\n"
        f"Respond ONLY in JSON with these exact keys:\n"
        f"  severity (one of: Low / Medium / High / Critical),\n"
        f"  explanation (1 sentence plain English),\n"
        f"  recommendation (1 actionable sentence)."
    )

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=10)
        response.raise_for_status()
        result = response.json()

        content = result.get("response", "")
        return _extract_json(content)
    except Exception:
        return None


def analyze_threat(event_type: str, raw_log: str, source_ip: str) -> dict:
    """Analyzes a security event using OpenRouter, with Ollama as fallback."""
    prompt = (
        f"You are a cybersecurity analyst. Analyze this security event.\n"
        f"Event type: {event_type}\n"
        f"Raw log: {raw_log}\n"
        f"Source IP: {source_ip}\n"
        f"Respond ONLY in JSON with these exact keys:\n"
        f"  severity (one of: Low / Medium / High / Critical),\n"
        f"  explanation (1 sentence plain English),\n"
        f"  recommendation (1 actionable sentence)."
    )

    fallback = {
        "severity": "Medium",
        "explanation": "Analysis unavailable — AI services not reachable.",
        "recommendation": "Review the event manually.",
    }

    # 1. Try OpenRouter
    if OPENROUTER_API_KEY:
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "HTTP-Referer": "https://raven-soc.local",
            "X-Title": "RAVEN 2.0",
            "Content-Type": "application/json",
        }
        payload = {
            "model": AI_MODEL,
            "messages": [{"role": "user", "content": prompt}],
        }

        try:
            response = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=15)
            response.raise_for_status()
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            parsed = _extract_json(content)
            if parsed:
                severity = parsed.get("severity", "Medium")
                if severity not in _VALID_SEVERITIES:
                    severity = "Medium"
                return {
                    "severity": severity,
                    "explanation": str(parsed.get("explanation", fallback["explanation"])),
                    "recommendation": str(parsed.get("recommendation", fallback["recommendation"])),
                }
        except Exception as e:
            print(f"[Analyzer] OpenRouter failed: {e}. Trying Ollama fallback...")

    # 2. Try Ollama
    ollama_parsed = _analyze_with_ollama(event_type, raw_log, source_ip)
    if ollama_parsed:
        severity = ollama_parsed.get("severity", "Medium")
        if severity not in _VALID_SEVERITIES:
            severity = "Medium"
        return {
            "severity": severity,
            "explanation": str(ollama_parsed.get("explanation", fallback["explanation"])),
            "recommendation": str(ollama_parsed.get("recommendation", fallback["recommendation"])),
        }

    # 3. Final Static Fallback
    return fallback

def check_ip_reputation(ip: str) -> dict:
    """Queries AbuseIPDB API for IP reputation."""
    fallback = {
        "abuse_score": 0,
        "total_reports": 0,
        "is_public": True,
        "usage_type": "Unknown",
        "isp": "Unknown"
    }

    if re.match(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)", ip):
        fallback["is_public"] = False
        return fallback

    if not ABUSEIPDB_API_KEY:
        return fallback

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "is_public": data.get("isPublic", True),
                "usage_type": data.get("usageType", "Unknown"),
                "isp": data.get("isp", "Unknown")
            }
        return fallback
    except Exception as e:
        print(f"[Analyzer] AbuseIPDB error: {e}")
        return fallback


if __name__ == "__main__":
    test_result = analyze_threat(
        event_type="Failed SSH",
        raw_log="Failed password for root from 192.168.1.100 port 50212 ssh2",
        source_ip="192.168.1.100",
    )
    print(json.dumps(test_result, indent=2))

def check_file_hash_reputation(sha256: str) -> dict:
    """Queries VirusTotal v3 for file hash reputation."""
    fallback = {"malicious": 0, "undetected": 0, "total_engines": 0, "verdict": "Unknown"}
    if not VIRUSTOTAL_API_KEY:
        return fallback

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "verdict": "Malicious" if stats.get("malicious", 0) > 3 else "Clean"
            }
        return fallback
    except Exception as e:
        print(f"[Analyzer] VirusTotal error: {e}")
        return fallback

def check_ip_shodan(ip: str) -> dict:
    """Queries Shodan for IP information and open ports."""
    fallback = {"open_ports": [], "org": "Unknown", "vulns": 0}
    if not SHODAN_API_KEY:
        return fallback

    url = f"https://api.shodan.io/host/{ip}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                "open_ports": data.get("ports", []),
                "org": data.get("org", "Unknown"),
                "vulns": len(data.get("vulns", []))
            }
        return fallback
    except Exception as e:
        print(f"[Analyzer] Shodan error: {e}")
        return fallback
