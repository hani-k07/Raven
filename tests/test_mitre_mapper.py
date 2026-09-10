import pytest
from mitre_mapper import get_mitre

def test_get_mitre_known():
    """Verify known event types return correct mapping."""
    res = get_mitre("SSH_BRUTE_FORCE")
    assert res["tactic_name"] == "Credential Access"
    assert res["technique_id"] == "T1110"

def test_get_mitre_unknown():
    """Verify unknown event types return fallback."""
    res = get_mitre("SOME_RANDOM_EVENT")
    assert res["tactic_name"] == "Unknown"
    assert res["technique_id"] == "Unknown"
