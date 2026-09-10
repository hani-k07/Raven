import os
import subprocess
import platform
from datetime import datetime
from config import validate_config

def block_ip(ip: str) -> bool:
    """Blocks an IP address using the host firewall."""
    system = platform.system()
    try:
        if system == "Windows":
            # Use netsh to add a firewall rule
            cmd = f'netsh advfirewall firewall add rule name="RAVEN_BLOCK_{ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
        elif system == "Linux":
            # Use iptables to block IP
            cmd = f'iptables -A INPUT -s {ip} -j DROP'
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
        else:
            print(f"[Containment] Unsupported OS: {system}")
            return False
        
        print(f"[Containment] Successfully blocked IP: {ip}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[Containment] Error blocking IP {ip}: {e}")
        return False

def kill_process(pid: int) -> bool:
    """Terminates a malicious process by PID."""
    try:
        import psutil
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"[Containment] Successfully terminated process {pid} ({proc.name()})")
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
        print(f"[Containment] Error killing process {pid}: {e}")
        return False

def auto_contain(threat: dict) -> bool:
    """
    Decides whether to automatically contain a threat based on severity and type.
    
    Returns True if containment was attempted.
    """
    severity = threat.get("severity", "Low")
    event_type = threat.get("event_type", "Unknown")
    source_ip = threat.get("source_ip", None)
    
    # Only auto-contain Critical threats or specific high-risk event types
    if severity == "Critical" or event_type in ("HONEYPOT_PORTSCAN", "FILE_INTEGRITY_CHANGE"):
        if source_ip and source_ip != "local":
            return block_ip(source_ip)
            
    return False

if __name__ == "__main__":
    # Test containment (requires admin privileges for firewall)
    print("Testing containment module...")
    # This will likely fail without admin, but we test the logic
    success = block_ip("1.2.3.4")
    print(f"Block IP 1.2.3.4: {'SUCCESS' if success else 'FAILED (expected if not admin)'}")
