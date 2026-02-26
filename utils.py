"""
Ghost Network Mapper — Utility Module
======================================
Provides helper functions for logging setup, network interface detection,
MAC vendor resolution, and other shared utilities.

Author: [Your Name]
Date: 2026-02-26
"""

import logging
import os
import socket
import struct
import time
from datetime import datetime
from typing import Dict, Optional

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOG_FORMAT: str = "[%(asctime)s] [%(levelname)s] %(message)s"
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"
MAC_VENDOR_API_URL: str = "https://api.macvendors.com/{mac}"
MAC_VENDOR_CACHE: Dict[str, str] = {}
DEFAULT_LOG_DIR: str = os.path.join("outputs", "logs")

ETHICS_DISCLAIMER: str = (
    "Ghost Network Mapper is intended strictly for educational purposes and "
    "authorized network testing only. Never run this tool on networks you do "
    "not own or have explicit written permission to scan. Unauthorized network "
    "scanning may be illegal in your jurisdiction."
)

RISKY_PORTS: Dict[int, str] = {
    21: "FTP - credentials transmitted in plaintext",
    22: "SSH - brute-force target",
    23: "Telnet - unencrypted remote access",
    25: "SMTP - mail relay abuse",
    53: "DNS - amplification attack risk",
    80: "HTTP - unencrypted web traffic",
    110: "POP3 - plaintext email",
    135: "MS RPC - lateral movement vector",
    139: "NetBIOS - SMB recon",
    143: "IMAP - plaintext email",
    443: "HTTPS - inspect for weak TLS",
    445: "SMB - ransomware/EternalBlue",
    1433: "MSSQL - database exposure",
    1521: "Oracle DB - database exposure",
    3306: "MySQL - database exposure",
    3389: "RDP - brute-force/BlueKeep",
    5432: "PostgreSQL - database exposure",
    5900: "VNC - remote desktop exposure",
    6379: "Redis - unauthenticated access",
    8080: "HTTP-alt - dev server exposure",
    8443: "HTTPS-alt - inspect for weak TLS",
    27017: "MongoDB - unauthenticated access",
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def setup_logger(log_path: str = DEFAULT_LOG_DIR) -> logging.Logger:
    """Configure and return a logger that writes to console and a timestamped file.

    The console handler uses Rich's RichHandler for colourful, structured output.
    The file handler writes plain-text entries to ``outputs/logs/``.

    Args:
        log_path: Directory where the log file will be created.

    Returns:
        A configured ``logging.Logger`` instance named ``ghost_mapper``.
    """
    from rich.logging import RichHandler

    os.makedirs(log_path, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_path, f"scan_{timestamp}.log")

    logger = logging.getLogger("ghost_mapper")
    logger.setLevel(logging.DEBUG)

    # Avoid duplicate handlers on repeated calls
    if logger.handlers:
        logger.handlers.clear()

    # Console handler — Rich
    console_handler = RichHandler(
        level=logging.INFO,
        show_time=True,
        show_path=False,
        markup=True,
    )
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console_handler)

    # File handler — plain text
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    )
    logger.addHandler(file_handler)

    logger.debug("Logger initialised — file: %s", log_file)
    return logger


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def get_local_subnet() -> str:
    """Detect the local machine's active network interface and return the subnet in CIDR.

    Attempts detection via ``netifaces`` first.  Falls back to a socket-based
    heuristic if ``netifaces`` is unavailable or fails.

    Returns:
        Subnet string in CIDR notation, e.g. ``"192.168.1.0/24"``.
    """
    # Attempt 1 — netifaces
    try:
        import netifaces  # type: ignore[import-untyped]

        gateways = netifaces.gateways()
        default_iface: Optional[str] = None

        if netifaces.AF_INET in gateways.get("default", {}):
            default_iface = gateways["default"][netifaces.AF_INET][1]

        if default_iface is None:
            # Pick the first non-loopback interface
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0].get("addr", "")
                    if ip and not ip.startswith("127."):
                        default_iface = iface
                        break

        if default_iface is not None:
            addrs = netifaces.ifaddresses(default_iface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                ip_addr = ip_info.get("addr", "")
                netmask = ip_info.get("netmask", "255.255.255.0")
                cidr = _netmask_to_cidr(netmask)
                network = _ip_to_network(ip_addr, netmask)
                return f"{network}/{cidr}"
    except Exception:
        pass  # Fall through to socket-based method

    # Attempt 2 — socket heuristic
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.connect(("8.8.8.8", 80))
        local_ip: str = sock.getsockname()[0]
        sock.close()
        # Assume /24
        octets = local_ip.rsplit(".", 1)
        return f"{octets[0]}.0/24"
    except OSError:
        return "192.168.1.0/24"


def _netmask_to_cidr(netmask: str) -> int:
    """Convert a dotted-decimal netmask to CIDR prefix length.

    Args:
        netmask: Netmask string, e.g. ``"255.255.255.0"``.

    Returns:
        Integer prefix length, e.g. ``24``.
    """
    return sum(bin(int(octet)).count("1") for octet in netmask.split("."))


def _ip_to_network(ip: str, netmask: str) -> str:
    """Compute the network address from an IP and netmask.

    Args:
        ip: Host IP address string.
        netmask: Dotted-decimal netmask.

    Returns:
        Network address string, e.g. ``"192.168.1.0"``.
    """
    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
    mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
    net_int = ip_int & mask_int
    return socket.inet_ntoa(struct.pack("!I", net_int))


# ---------------------------------------------------------------------------
# MAC vendor lookup
# ---------------------------------------------------------------------------
def get_vendor_from_mac(mac: str) -> str:
    """Resolve a MAC address OUI to the vendor name via macvendors.co API.

    Results are cached in-memory to avoid redundant HTTP requests.

    Args:
        mac: MAC address string (any common format).

    Returns:
        Vendor name string, or ``"Unknown"`` on failure.
    """
    if not mac or mac.lower() in ("unknown", "n/a", ""):
        return "Unknown"

    # Normalise to upper-case colon-separated
    cleaned = mac.upper().replace("-", ":").strip()
    oui = cleaned[:8]  # First 3 octets

    if oui in MAC_VENDOR_CACHE:
        return MAC_VENDOR_CACHE[oui]

    try:
        response = requests.get(
            MAC_VENDOR_API_URL.format(mac=oui),
            timeout=3,
        )
        if response.status_code == 200 and response.text.strip():
            vendor = response.text.strip()
            MAC_VENDOR_CACHE[oui] = vendor
            return vendor
    except (requests.RequestException, ValueError):
        pass

    MAC_VENDOR_CACHE[oui] = "Unknown"
    return "Unknown"


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def format_duration(seconds: float) -> str:
    """Convert elapsed seconds to a human-readable string.

    Args:
        seconds: Duration in seconds.

    Returns:
        Formatted string, e.g. ``"2m 34s"``.
    """
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


# ---------------------------------------------------------------------------
# Risky ports
# ---------------------------------------------------------------------------
def load_risky_ports() -> Dict[int, str]:
    """Return the dictionary of well-known risky ports with descriptions.

    Returns:
        Mapping of port number to risk description string.
    """
    return dict(RISKY_PORTS)
