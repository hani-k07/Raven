import pytest
import requests
from unittest.mock import patch, MagicMock
from analyzer import analyze_threat, _extract_json

def test_extract_json_clean():
    text = '{"severity": "High", "explanation": "test", "recommendation": "block"}'
    assert _extract_json(text) == {"severity": "High", "explanation": "test", "recommendation": "block"}

def test_extract_json_markdown():
    text = '```json\n{"severity": "Low", "explanation": "test", "recommendation": "ignore"}\n```'
    assert _extract_json(text) == {"severity": "Low", "explanation": "test", "recommendation": "ignore"}

def test_extract_json_noise():
    text = 'The result is: {"severity": "Medium", "explanation": "test", "recommendation": "verify"}'
    assert _extract_json(text) == {"severity": "Medium", "explanation": "test", "recommendation": "verify"}

@patch("requests.post")
def test_analyze_threat_success(mock_post):
    # Mock a successful OpenRouter response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": '{"severity": "Critical", "explanation": "Attack", "recommendation": "Block"}'}}]
    }
    mock_post.return_value = mock_resp

    # We need an API key for this path
    import os
    os.environ["OPENROUTER_API_KEY"] = "fake_key"

    res = analyze_threat("Event", "Log", "1.1.1.1")
    assert res["severity"] == "Critical"
    assert res["explanation"] == "Attack"

@patch("requests.post")
def test_analyze_threat_fallback(mock_post):
    # Mock a failure
    mock_post.side_effect = requests.exceptions.ConnectionError()

    import os
    os.environ["OPENROUTER_API_KEY"] = "fake_key"
    os.environ["OLLAMA_URL"] = "http://invalid"

    res = analyze_threat("Event", "Log", "1.1.1.1")
    assert res["severity"] == "Medium"
    assert "unavailable" in res["explanation"]
