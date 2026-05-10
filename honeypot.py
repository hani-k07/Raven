import socket
import threading
import sqlite3
from datetime import datetime
from pathlib import Path
from config import HONEYPOT_PORTS
from analyzer import analyze_threat

DB_PATH = Path(__file__).parent / "raven.db"

def handle_connection(client_socket: socket.socket, client_address: tuple, port: int) -> None:
    """Handles an individual honeypot connection."""
    attacker_ip, attacker_port = client_address
    try:
        client_socket.settimeout(5.0)
        payload_bytes = client_socket.recv(512)
        payload = payload_bytes.decode('utf-8', errors='replace')
        
        timestamp = datetime.now().isoformat()
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO honeypot_events (timestamp, attacker_ip, port, payload)
            VALUES (?, ?, ?, ?)
        """, (timestamp, attacker_ip, port, payload))
        conn.commit()
        
        analysis = analyze_threat("honeypot_connection", payload, attacker_ip)
        
        cursor.execute("""
            INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            attacker_ip,
            "HONEYPOT",
            f"Port {port} hit: {payload}",
            analysis.get('severity', 'High'),
            analysis.get('explanation', ''),
            analysis.get('recommendation', ''),
            False
        ))
        conn.commit()
        conn.close()
        
        print(f"[HONEYPOT] Connection on port {port} from {attacker_ip}")
        
    except Exception as e:
        print(f"Error handling honeypot connection from {attacker_ip}: {e}")
    finally:
        client_socket.close()

def start_honeypot_listener(port: int) -> None:
    """Starts a socket listener on a specific port."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(5)
        print(f"Honeypot listening on port {port}...")
        
        while True:
            client_socket, client_address = server_socket.accept()
            thread = threading.Thread(target=handle_connection, args=(client_socket, client_address, port), daemon=True)
            thread.start()
            
    except Exception as e:
        print(f"Failed to start honeypot on port {port}: {e}")
    finally:
        server_socket.close()

def start_honeypot(ports: list[int]) -> None:
    """Starts honeypot listeners for all specified ports."""
    threads = []
    for port in ports:
        thread = threading.Thread(target=start_honeypot_listener, args=(port,), daemon=True)
        thread.start()
        threads.append(thread)
        
    if __name__ == "__main__":
        for thread in threads:
            thread.join()

if __name__ == "__main__":
    print("Testing standalone honeypot.py on port 9999...")
    start_honeypot([9999])
