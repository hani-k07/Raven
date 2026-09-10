"""
RAVEN 2.0 — Advanced Deception Grid (Honeypot Engine)

Protocol-aware honeypot system with banner responses, HTTP request parsing,
multi-port scan detection, full session logging, and UDP DNS traps.

Supports: SSH, Telnet, FTP, SMTP, HTTP, MySQL, VNC, Redis, Elasticsearch,
          and a UDP DNS honeypot for detecting DNS reconnaissance.

All events are written to both honeypot_events and threats tables.
"""
import socket
import struct
import threading
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from config import HONEYPOT_PORTS
from analyzer import analyze_threat

DB_PATH = Path(__file__).parent / "raven.db"

# ── ANSI Colors (no colorama dependency) ──────────────────
_RED = "\033[91m"
_GRN = "\033[92m"
_YEL = "\033[93m"
_CYN = "\033[96m"
_RST = "\033[0m"
_BLD = "\033[1m"

# ── Protocol Banners ──────────────────────────────────────
PROTOCOL_BANNERS = {
    22:   b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    23:   b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f",  # Telnet IAC negotiation
    21:   b"220 FTP server ready (ProFTPD 1.3.6)\r\n",
    25:   b"220 mail.corp.local ESMTP Postfix\r\n",
    80:   None,   # HTTP: respond after reading request
    443:  None,   # TLS: skip banner (attacker expects TLS handshake)
    3306: b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x35\x00",  # MySQL 8.0.35 handshake stub
    5900: b"RFB 003.008\n",    # VNC protocol version
    6379: b"+PONG\r\n",        # Redis PING response
    8080: None,   # HTTP alt — respond after reading
    2222: b"SSH-2.0-OpenSSH_7.4\r\n",  # Legacy SSH decoy
    2121: b"220 FTP archive ready (vsftpd 3.0.3)\r\n",
    9200: None,   # Elasticsearch — respond to GET /
    9999: b"Welcome to RAVEN Decoy Service\r\n",
}

# ── HTTP Honeypot Constants ───────────────────────────────
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Apache/2.4.41 (Ubuntu)\r\n"
    b"Content-Type: text/html; charset=UTF-8\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"<!DOCTYPE html><html><head><title>Login</title></head>"
    b"<body><h2>Authentication Required</h2>"
    b"<form method='post'><input name='user' placeholder='Username'>"
    b"<input name='pass' type='password' placeholder='Password'>"
    b"<button>Sign In</button></form></body></html>\r\n"
)

ELASTICSEARCH_RESPONSE = (
    b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
    b'{"name":"raven-node","cluster_name":"production","version":{"number":"7.17.9"},"tagline":"You Know, for Search"}\r\n'
)

SENSITIVE_PATHS = [
    "/.env", "/wp-admin", "/admin", "/config", "/shell", "/cmd",
    "/phpinfo", "/actuator", "/.git", "/wp-login", "/phpmyadmin",
    "/server-status", "/debug", "/console", "/api/v1/token",
]

# ── Multi-Port Scan Tracking ─────────────────────────────
_ip_hits: dict[str, list[tuple[int, float]]] = {}  # ip -> [(port, timestamp), ...]
_ip_lock = threading.Lock()
_SCAN_WINDOW = 60.0    # seconds
_SCAN_THRESHOLD = 3    # ports

# ── Per-Port Concurrency Limiter ──────────────────────────
_port_semaphores: dict[int, threading.Semaphore] = {}
_sem_lock = threading.Lock()


def _get_semaphore(port: int) -> threading.Semaphore:
    """Get or create a semaphore for a given port (max 5 concurrent connections)."""
    with _sem_lock:
        if port not in _port_semaphores:
            _port_semaphores[port] = threading.Semaphore(5)
        return _port_semaphores[port]


def _classify_event(port: int, payload: str) -> tuple[str, str]:
    """Classify event_type and severity based on port and payload content.

    Returns:
        Tuple of (event_type, severity).
    """
    if port in (22, 2222):
        return "HONEYPOT_SSH", "High"
    if port in (80, 8080, 9200):
        if any(p in payload.lower() for p in SENSITIVE_PATHS):
            return "HONEYPOT_WEB_PROBE", "Critical"
        return "HONEYPOT_HTTP", "Medium"
    if port == 3306:
        return "HONEYPOT_MYSQL", "High"
    if port == 6379:
        return "HONEYPOT_REDIS", "High"
    if port == 5900:
        return "HONEYPOT_VNC", "High"
    if port == 23:
        return "HONEYPOT_TELNET", "Medium"
    if port in (21, 2121):
        return "HONEYPOT_FTP", "Medium"
    if port == 25:
        return "HONEYPOT_SMTP", "Medium"
    if port == 53:
        return "HONEYPOT_DNS", "Medium"
    return "HONEYPOT_GENERIC", "Medium"


def _check_portscan(ip: str, port: int) -> bool:
    """Track connection and detect multi-port scanning.

    Returns True if this connection triggered a portscan alert.
    """
    now = time.time()
    with _ip_lock:
        if ip not in _ip_hits:
            _ip_hits[ip] = []

        # Prune old entries outside the scan window
        _ip_hits[ip] = [(p, t) for p, t in _ip_hits[ip] if now - t < _SCAN_WINDOW]
        _ip_hits[ip].append((port, now))

        # Count unique ports hit
        unique_ports = set(p for p, _ in _ip_hits[ip])
        if len(unique_ports) >= _SCAN_THRESHOLD:
            # Check if we already alerted for this IP in this window
            # (avoid duplicate portscan alerts)
            if not hasattr(_check_portscan, '_alerted'):
                _check_portscan._alerted = {}
            last_alert = _check_portscan._alerted.get(ip, 0)
            if now - last_alert > _SCAN_WINDOW:
                _check_portscan._alerted[ip] = now
                _inject_portscan_alert(ip, unique_ports)
                return True
    return False


def _inject_portscan_alert(ip: str, ports: set[int]):
    """Insert a HONEYPOT_PORTSCAN threat for an IP that hit multiple ports."""
    timestamp = datetime.now().isoformat()
    port_list = ", ".join(str(p) for p in sorted(ports))
    n = len(ports)
    raw_log = f"Multi-port scan: {ip} probed {n} honeypot ports ({port_list}) within {_SCAN_WINDOW:.0f}s"
    ai_text = (
        f"Attacker {ip} has probed {n} honeypot ports in under {_SCAN_WINDOW:.0f} seconds — "
        f"active network mapping in progress. Ports hit: {port_list}."
    )
    recommendation = "Block IP at perimeter firewall. Flag for threat intel enrichment."

    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (timestamp, ip, "HONEYPOT_PORTSCAN", raw_log, "Critical", ai_text, recommendation, 0),
        )
        conn.commit()
        print(f"  {_RED}{_BLD}[PORTSCAN]{_RST} {ip} hit {n} ports — Critical alert injected")
    except Exception as e:
        print(f"  {_RED}[ERROR] Portscan DB write: {e}{_RST}")
    finally:
        if conn:
            conn.close()


def _parse_http_request(payload: str) -> dict:
    """Extract method, path, User-Agent, and body from an HTTP request.

    Returns:
        Dict with keys: method, path, user_agent, body.
    """
    result = {"method": "?", "path": "/", "user_agent": "Unknown", "body": ""}
    lines = payload.split("\r\n")
    if not lines:
        return result

    # Request line
    parts = lines[0].split(" ")
    if len(parts) >= 2:
        result["method"] = parts[0]
        result["path"] = parts[1]

    # Headers
    for line in lines[1:]:
        if line.lower().startswith("user-agent:"):
            result["user_agent"] = line.split(":", 1)[1].strip()
        if line == "":
            # Everything after blank line is body
            idx = payload.find("\r\n\r\n")
            if idx != -1:
                result["body"] = payload[idx + 4:]
            break

    return result


def _extract_ssh_version(payload: str) -> str:
    """Extract SSH client version string from handshake payload."""
    for line in payload.split("\n"):
        line = line.strip()
        if line.startswith("SSH-"):
            return line
    return "Unknown SSH client"


def _read_full_session(client_socket: socket.socket, max_bytes: int = 4096) -> str:
    """Read up to max_bytes from a client in a loop, handling slow senders.

    Returns decoded payload string.
    """
    chunks = []
    total = 0
    try:
        while True:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
    except socket.timeout:
        pass  # Timeout is expected — attacker may disconnect or be slow
    except OSError:
        pass  # Socket closed
    return b"".join(chunks).decode("utf-8", errors="replace")


def _is_ip_allowlisted(ip: str) -> bool:
    """Checks if an IP is in the allowlist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM ip_allowlist WHERE ip = ?", (ip,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def _db_write(timestamp: str, ip: str, port: int, payload: str,
              event_type: str, severity: str, raw_log: str):
    """Write event to both honeypot_events and threats tables.

    Uses AI analysis if available, falls back to local classification.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Honeypot events table
        cursor.execute(
            "INSERT INTO honeypot_events (timestamp, attacker_ip, port, payload) VALUES (?,?,?,?)",
            (timestamp, ip, port, payload[:500]),
        )

        # Try AI analysis in background — but don't block on failure
        ai_analysis = f"Honeypot {event_type} event on port {port}. Attacker payload captured for analysis."
        recommendation = "Monitor attacker behavior. Add IP to watchlist."

        try:
            analysis = analyze_threat(event_type, raw_log[:300], ip)
            if analysis.get("explanation"):
                ai_analysis = analysis["explanation"]
            if analysis.get("recommendation"):
                recommendation = analysis["recommendation"]
            # Use AI-determined severity if valid
            ai_sev = analysis.get("severity", "")
            if ai_sev in ("Low", "Medium", "High", "Critical"):
                severity = ai_sev
        except Exception:
            pass  # Fall back to local classification

        # Check allowlist
        if _is_ip_allowlisted(ip):
            severity = "Low"
            ai_analysis = f"[ALLOWLISTED] {ai_analysis}"

        cursor.execute(
            "INSERT INTO threats (timestamp, source_ip, event_type, raw_log, severity, ai_analysis, recommendation, alerted) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (timestamp, ip, event_type, raw_log[:500], severity, ai_analysis, recommendation, 0),
        )
        conn.commit()
    except Exception as e:
        print(f"  {_RED}[DB ERROR] {e}{_RST}")
    finally:
        if conn:
            conn.close()


# ── TCP Connection Handler ────────────────────────────────

def handle_connection(client_socket: socket.socket, client_address: tuple, port: int) -> None:
    """Handle an individual TCP honeypot connection with protocol-aware responses.

    Sends appropriate banner, reads full session payload, classifies the event,
    and logs to both database tables.
    """
    ip, attacker_port = client_address
    sem = _get_semaphore(port)

    if not sem.acquire(blocking=False):
        # Too many concurrent connections on this port — drop silently
        client_socket.close()
        return

    try:
        client_socket.settimeout(8.0)
        timestamp = datetime.now().isoformat()

        # Send protocol banner if defined
        banner = PROTOCOL_BANNERS.get(port)
        if banner:
            try:
                client_socket.sendall(banner)
            except OSError:
                pass

        # Read full session payload
        payload = _read_full_session(client_socket)

        # HTTP ports: parse request and send response
        if port in (80, 8080):
            http = _parse_http_request(payload)
            try:
                client_socket.sendall(HTTP_RESPONSE)
            except OSError:
                pass
            fingerprint = f"HTTP {http['method']} {http['path']} | UA: {http['user_agent']}"
            if http["body"]:
                fingerprint += f" | Body: {http['body'][:100]}"
            raw_log = f"Port {port} — {fingerprint}"

        elif port == 9200:
            # Elasticsearch honeypot
            try:
                client_socket.sendall(ELASTICSEARCH_RESPONSE)
            except OSError:
                pass
            http = _parse_http_request(payload)
            raw_log = f"Port {port} — Elasticsearch probe: {http['method']} {http['path']}"

        elif port in (22, 2222):
            # SSH: extract client version
            ssh_ver = _extract_ssh_version(payload)
            raw_log = f"Port {port} SSH — Client: {ssh_ver} | Payload: {payload[:150]}"

        else:
            raw_log = f"Port {port} hit — Payload ({len(payload)} bytes): {payload[:200]}"

        # Classify event
        event_type, severity = _classify_event(port, payload)

        # Log to console
        sev_color = {
            "Critical": _RED, "High": _YEL, "Medium": _CYN,
        }.get(severity, _GRN)
        print(f"  {sev_color}[{event_type:<20}]{_RST} {ip}:{attacker_port} -> port {port} | {severity}")

        # Write to database
        _db_write(timestamp, ip, port, payload, event_type, severity, raw_log)

        # Check for multi-port scan
        _check_portscan(ip, port)

    except Exception as e:
        print(f"  {_RED}[ERROR] Honeypot handler port {port}: {e}{_RST}")
    finally:
        sem.release()
        try:
            client_socket.close()
        except OSError:
            pass


# ── UDP DNS Honeypot ──────────────────────────────────────

def _extract_dns_qname(data: bytes) -> str:
    """Extract the queried domain name (QNAME) from a raw DNS packet.

    DNS QNAME starts at byte 12 and is a sequence of length-prefixed labels
    terminated by a zero byte.

    Returns:
        The queried domain as a dotted string, or 'unknown' on failure.
    """
    try:
        pos = 12  # Skip DNS header (12 bytes)
        labels = []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            pos += 1
            labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
        return ".".join(labels) if labels else "unknown"
    except Exception:
        return "unknown"


def _start_udp_dns_honeypot(port: int = 53) -> None:
    """Start a UDP honeypot on port 53 to capture DNS reconnaissance queries.

    Logs queried domain names and injects HONEYPOT_DNS events.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        print(f"  {_GRN}[DNS TRAP]{_RST} UDP honeypot listening on port {port}")
    except Exception as e:
        print(f"  {_YEL}[DNS TRAP]{_RST} Failed to bind UDP port {port}: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            ip = addr[0]
            timestamp = datetime.now().isoformat()
            qname = _extract_dns_qname(data)
            payload = f"DNS query for '{qname}' ({len(data)} bytes)"
            raw_log = f"Port 53/UDP — DNS lookup: {qname} from {ip}"

            print(f"  {_CYN}[HONEYPOT_DNS        ]{_RST} {ip} → port 53/UDP | query: {qname}")

            _db_write(timestamp, ip, 53, payload, "HONEYPOT_DNS", "Medium", raw_log)
            _check_portscan(ip, 53)

        except Exception as e:
            print(f"  {_RED}[DNS ERROR] {e}{_RST}")


# ── TCP Listener ──────────────────────────────────────────

def start_honeypot_listener(port: int) -> None:
    """Start a TCP socket listener on a specific honeypot port.

    Accepts connections and dispatches them to handle_connection
    with per-port concurrency limiting (max 5 threads).
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind(("0.0.0.0", port))
        server_socket.listen(5)
        proto = {
            22: "SSH", 23: "Telnet", 21: "FTP", 25: "SMTP",
            80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5900: "VNC",
            6379: "Redis", 8080: "HTTP-Alt", 2222: "SSH-Decoy",
            2121: "FTP-Decoy", 9200: "Elasticsearch", 9999: "Generic",
        }.get(port, "TCP")
        print(f"  {_GRN}[LISTEN]{_RST} Honeypot {proto} on port {port}")

        while True:
            try:
                client_socket, client_address = server_socket.accept()
                thread = threading.Thread(
                    target=handle_connection,
                    args=(client_socket, client_address, port),
                    daemon=True,
                )
                thread.start()
            except OSError:
                break  # Socket closed during shutdown

    except PermissionError:
        print(f"  {_YEL}[SKIP]{_RST} Port {port} requires elevated privileges — skipping")
    except OSError as e:
        print(f"  {_RED}[FAIL]{_RST} Port {port}: {e}")
    except KeyboardInterrupt:
        print(f"\n  {_YEL}[STOP]{_RST} Honeypot on port {port} shutting down")
    finally:
        try:
            server_socket.close()
        except OSError:
            pass


# ── Public API ────────────────────────────────────────────

def start_honeypot(ports: list[int]) -> None:
    """Start honeypot listeners for all specified ports as daemon threads.

    Launches one TCP listener thread per port, plus a UDP DNS trap
    if port 53 is in the list.
    """
    if not ports:
        print(f"  {_YEL}[HONEYPOT]{_RST} No ports configured — deception grid offline")
        return

    print(f"  {_GRN}[HONEYPOT]{_RST} Initializing deception grid on {len(ports)} ports...")

    for port in ports:
        if port == 53:
            # DNS uses UDP
            thread = threading.Thread(target=_start_udp_dns_honeypot, args=(53,), daemon=True)
        else:
            thread = threading.Thread(target=start_honeypot_listener, args=(port,), daemon=True)
        thread.start()

    print(f"  {_GRN}[HONEYPOT]{_RST} Deception grid ACTIVE — {len(ports)} traps deployed")


if __name__ == "__main__":
    print(f"\n{_BLD}RAVEN 2.0 — Standalone Honeypot Test{_RST}")
    print(f"Testing on ports 9999 (TCP) + 2222 (SSH decoy)\n")
    start_honeypot([9999, 2222])

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{_YEL}Honeypot stopped.{_RST}")
