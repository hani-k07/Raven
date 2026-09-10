import os
import json
import requests
from unittest.mock import patch

# Mock env vars before importing analyzer
os.environ["OPENROUTER_API_KEY"] = ""
os.environ["OLLAMA_URL"] = "http://localhost:9999/api/generate" # Non-existent port
os.environ["OLLAMA_MODEL"] = "llama3.1:8b"

import analyzer

def test_fallback_chain():
    print("Testing fallback chain (No OpenRouter, No Ollama)...")
    result = analyzer.analyze_threat(
        event_type="SSH Brute Force",
        raw_log="Failed password for root...",
        source_ip="1.1.1.1"
    )
    print(f"Result: {json.dumps(result, indent=2)}")
    assert result["severity"] == "Medium"
    assert "AI services not reachable" in result["explanation"]
    print("SUCCESS: Fallback chain test passed.")

def test_ollama_payload():
    print("\nTesting Ollama code path (Non-existent host)...")
    # We want to verify it doesn't crash and returns None
    result = analyzer._analyze_with_ollama(
        event_type="Test",
        raw_log="Test log",
        source_ip="1.2.3.4"
    )
    print(f"Result: {result}")
    assert result is None
    print("SUCCESS: Ollama payload test passed.")

if __name__ == "__main__":
    try:
        test_fallback_chain()
        test_ollama_payload()
        print("\nAll Phase 7 tests passed!")
    except Exception as e:
        print(f"\nFAILED: {e}")
        exit(1)
