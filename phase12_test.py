import json
import os

# Ensure API keys are empty
os.environ["VIRUSTOTAL_API_KEY"] = ""
os.environ["SHODAN_API_KEY"] = ""

import analyzer

def test_vt_fallback():
    print("Testing VirusTotal fallback...")
    # Dummy hash
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    result = analyzer.check_file_hash_reputation(sha256)
    print(f"Result: {json.dumps(result, indent=2)}")
    assert result["verdict"] == "Unknown"
    assert result["malicious"] == 0
    print("SUCCESS: VirusTotal fallback works.")

def test_shodan_fallback():
    print("\nTesting Shodan fallback...")
    ip = "8.8.8.8"
    result = analyzer.check_ip_shodan(ip)
    print(f"Result: {json.dumps(result, indent=2)}")
    assert result["org"] == "Unknown"
    assert result["open_ports"] == []
    print("SUCCESS: Shodan fallback works.")

if __name__ == "__main__":
    try:
        test_vt_fallback()
        test_shodan_fallback()
        print("\nAll Phase 12 tests passed!")
    except Exception as e:
        print(f"\nFAILED: {e}")
        exit(1)
