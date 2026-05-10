import json
import requests
from config import OPENROUTER_API_KEY, AI_MODEL, OPENROUTER_URL

def analyze_threat(event_type: str, raw_log: str, source_ip: str) -> dict:
    """Analyzes a security event using the OpenRouter API and returns a structured JSON response."""
    prompt = f"""You are a cybersecurity analyst. Analyze this security event.
Event type: {event_type}
Raw log: {raw_log}
Source IP: {source_ip}
Respond ONLY in JSON with keys:
  severity (one of: Low / Medium / High / Critical),
  explanation (1 sentence plain English),
  recommendation (1 actionable sentence)."""

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "HTTP-Referer": "https://raven-soc.local",
        "X-Title": "RAVEN 2.0",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": AI_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_object"}
    }
    
    fallback = {
        "severity": "Medium",
        "explanation": "Analysis unavailable",
        "recommendation": "Review event manually"
    }

    try:
        response = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
        
        if content.startswith("```json"):
            content = content[7:-3].strip()
        elif content.startswith("```"):
            content = content[3:-3].strip()
            
        parsed_content = json.loads(content)
        
        return {
            "severity": parsed_content.get("severity", fallback["severity"]),
            "explanation": parsed_content.get("explanation", fallback["explanation"]),
            "recommendation": parsed_content.get("recommendation", fallback["recommendation"])
        }
        
    except Exception as e:
        print(f"Error calling OpenRouter API: {e}")
        return fallback

if __name__ == "__main__":
    print("Testing standalone analyzer.py...")
    test_result = analyze_threat(
        event_type="Failed SSH",
        raw_log="Failed password for root from 192.168.1.100 port 50212 ssh2",
        source_ip="192.168.1.100"
    )
    print(json.dumps(test_result, indent=2))
