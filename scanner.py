"""
Ghost Network Mapper — Network Scanner Module
===============================================
Performs network host discovery via ARP/ping sweeps and detailed port scanning
using python-nmap.  Supports multithreaded scanning with Rich progress bars.

Author: [Your Name]
Date: 2026-02-26
"""

import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

# Ensure Nmap is discoverable on Windows even if not in system PATH
_NMAP_DIRS = [
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
]
_NMAP_SEARCH_PATH: tuple = ()
for _d in _NMAP_DIRS:
    _nmap_exe = os.path.join(_d, "nmap.exe")
    if os.path.isfile(_nmap_exe):
        _NMAP_SEARCH_PATH = (_nmap_exe,)
        if _d not in os.environ.get("PATH", ""):
            os.environ["PATH"] = _d + os.pathsep + os.environ.get("PATH", "")
        break

import nmap  # python-nmap

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from utils import get_vendor_from_mac

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_PORT_RANGE: str = "1-1024"
FULL_PORT_RANGE: str = "1-65535"
MAX_WORKERS: int = 10
BANNER_PORTS: List[int] = [21, 22, 80, 443, 8080]
BANNER_TIMEOUT: float = 2.0


class NetworkScanner:
    """Discovers hosts on a subnet and performs port / service scanning.

    Uses python-nmap for host discovery (``-sn``) and detailed port scanning
    (``-sV -O``).  Scanning is parallelised with ``ThreadPoolExecutor``.

    Attributes:
        subnet: Target subnet in CIDR notation.
        port_range: Nmap-compatible port range string.
        timeout: Maximum time in seconds for overall scan.
        logger: Configured ``logging.Logger`` instance.
    """

    def __init__(
        self,
        subnet: str,
        port_range: str = DEFAULT_PORT_RANGE,
        timeout: int = 120,
        logger: Any = None,
    ) -> None:
        """Initialise the scanner.

        Args:
            subnet: Target subnet in CIDR notation, e.g. ``"192.168.1.0/24"``.
            port_range: Port range to scan (``"1-1024"`` or ``"1-65535"``).
            timeout: Overall scan timeout in seconds.
            logger: A ``logging.Logger`` instance.
        """
        self.subnet: str = subnet
        self.port_range: str = port_range
        self.timeout: int = timeout
        self.logger = logger

        try:
            self.nm: nmap.PortScanner = nmap.PortScanner(
                nmap_search_path=_NMAP_SEARCH_PATH
            ) if _NMAP_SEARCH_PATH else nmap.PortScanner()
        except nmap.PortScannerError as exc:
            msg = (
                "Nmap is not installed or not found in PATH. "
                "Please install Nmap: https://nmap.org/download.html"
            )
            if self.logger:
                self.logger.error(msg)
            raise RuntimeError(msg) from exc

    # ------------------------------------------------------------------
    # Host discovery
    # ------------------------------------------------------------------
    def discover_hosts(self) -> List[Dict[str, Any]]:
        """Run an Nmap ping scan (``-sn``) to discover live hosts.

        Returns:
            List of dicts with keys: ``ip``, ``mac``, ``hostname``,
            ``vendor``, ``status``.
        """
        if self.logger:
            self.logger.info("Starting host discovery on [bold cyan]%s[/]", self.subnet)

        hosts: List[Dict[str, Any]] = []
        start = time.time()

        try:
            self.nm.scan(hosts=self.subnet, arguments="-sn", timeout=self.timeout)
        except Exception as exc:
            if self.logger:
                self.logger.error("Host discovery failed: %s", exc)
            return hosts

        all_hosts = list(self.nm.all_hosts())

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("Discovering hosts…", total=len(all_hosts))

            def _process_host(ip: str) -> Optional[Dict[str, Any]]:
                try:
                    host_info = self.nm[ip]
                    mac = "N/A"
                    vendor = "Unknown"

                    if "mac" in host_info.get("addresses", {}):
                        mac = host_info["addresses"]["mac"]
                        # Try nmap-provided vendor first
                        if host_info.get("vendor"):
                            vendor = list(host_info["vendor"].values())[0]
                        else:
                            vendor = get_vendor_from_mac(mac)

                    hostname = ""
                    if host_info.hostnames():
                        hostname = host_info.hostnames()[0].get("name", "")

                    return {
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname or "N/A",
                        "vendor": vendor,
                        "status": host_info.state(),
                    }
                except (KeyError, IndexError):
                    return None

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(_process_host, ip): ip for ip in all_hosts}
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        hosts.append(result)
                    progress.advance(task)

        elapsed = time.time() - start
        if self.logger:
            self.logger.info(
                "Discovery complete — [green]%d hosts[/] found in %.1fs",
                len(hosts),
                elapsed,
            )
        return hosts

    # ------------------------------------------------------------------
    # Port scanning
    # ------------------------------------------------------------------
    def scan_ports(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Perform detailed port + service scanning for each discovered host.

        For every host the scan collects open ports, service versions, OS
        guesses, and service banners.

        Args:
            hosts: List of host dicts produced by ``discover_hosts()``.

        Returns:
            The same list enriched with ``open_ports``, ``os_guess``,
            and ``scan_duration`` keys.
        """
        if not hosts:
            if self.logger:
                self.logger.warning("No hosts to scan.")
            return hosts

        if self.logger:
            self.logger.info(
                "Port scanning [bold cyan]%d hosts[/] — range %s",
                len(hosts),
                self.port_range,
            )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("Scanning ports…", total=len(hosts))

            def _scan_host(host: Dict[str, Any]) -> Dict[str, Any]:
                ip = host["ip"]
                host_start = time.time()
                open_ports: List[Dict[str, Any]] = []
                os_guess: str = "Unknown"

                try:
                    scanner = (
                        nmap.PortScanner(nmap_search_path=_NMAP_SEARCH_PATH)
                        if _NMAP_SEARCH_PATH
                        else nmap.PortScanner()
                    )
                    # Use -sV for service detection; -O requires root/admin
                    scan_args = f"-sV -p {self.port_range} --host-timeout {self.timeout}s"
                    try:
                        scanner.scan(hosts=ip, arguments=f"-O {scan_args}")
                    except nmap.PortScannerError:
                        # -O requires elevated privileges — retry without
                        scanner.scan(hosts=ip, arguments=scan_args)

                    if ip in scanner.all_hosts():
                        host_data = scanner[ip]

                        # OS detection results
                        osmatch = host_data.get("osmatch", [])
                        if osmatch:
                            os_guess = osmatch[0].get("name", "Unknown")

                        # Iterate protocols and ports
                        for proto in host_data.all_protocols():
                            ports = sorted(host_data[proto].keys())
                            for port in ports:
                                port_info = host_data[proto][port]
                                if port_info.get("state") == "open":
                                    entry: Dict[str, Any] = {
                                        "port": port,
                                        "protocol": proto,
                                        "state": port_info["state"],
                                        "service": port_info.get("name", "unknown"),
                                        "version": port_info.get("version", ""),
                                        "banner": "",
                                    }
                                    # Grab banner for key ports
                                    if port in BANNER_PORTS:
                                        entry["banner"] = _grab_banner(ip, port)
                                    open_ports.append(entry)

                except PermissionError:
                    if self.logger:
                        self.logger.warning(
                            "Permission denied scanning %s — run as admin/root.",
                            ip,
                        )
                except Exception as exc:
                    if self.logger:
                        self.logger.error("Error scanning %s: %s", ip, exc)

                # TTL-based OS hint fallback
                if os_guess == "Unknown":
                    os_guess = _ttl_os_hint(ip)

                host["open_ports"] = open_ports
                host["os_guess"] = os_guess
                host["scan_duration"] = round(time.time() - host_start, 2)
                return host

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(_scan_host, h): h for h in hosts}
                for future in as_completed(futures):
                    future.result()  # Ensures exceptions propagate
                    progress.advance(task)

        if self.logger:
            total_ports = sum(len(h.get("open_ports", [])) for h in hosts)
            self.logger.info(
                "Port scan complete — [green]%d open ports[/] across %d hosts",
                total_ports,
                len(hosts),
            )

        return hosts

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------
    def run(self) -> List[Dict[str, Any]]:
        """Execute the full scan pipeline: discovery → port scan.

        Returns:
            Fully enriched list of host dictionaries.
        """
        if self.logger:
            self.logger.info("=" * 60)
            self.logger.info("Ghost Network Mapper — Scan Started")
            self.logger.info("Subnet : %s", self.subnet)
            self.logger.info("Ports  : %s", self.port_range)
            self.logger.info("Timeout: %ds", self.timeout)
            self.logger.info("=" * 60)

        start = time.time()
        hosts = self.discover_hosts()
        hosts = self.scan_ports(hosts)
        elapsed = time.time() - start

        if self.logger:
            self.logger.info(
                "Full scan finished in [bold green]%.1fs[/bold green]", elapsed
            )

        return hosts


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _grab_banner(ip: str, port: int) -> str:
    """Attempt to grab a service banner from an open port via a raw socket.

    Args:
        ip: Target IP address.
        port: Target port number.

    Returns:
        Banner string (first 256 bytes) or empty string on failure.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(BANNER_TIMEOUT)
        sock.connect((ip, port))

        # Send a minimal HTTP request for HTTP-like ports
        if port in (80, 443, 8080, 8443):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())

        banner = sock.recv(256).decode("utf-8", errors="replace").strip()
        sock.close()
        return banner
    except (OSError, UnicodeDecodeError):
        return ""


def _ttl_os_hint(ip: str) -> str:
    """Estimate the remote OS based on the default TTL of a ping reply.

    TTL ≈ 64  → Linux / macOS
    TTL ≈ 128 → Windows
    TTL ≈ 255 → Network device (router/switch)

    Args:
        ip: Target IP address.

    Returns:
        Human-readable OS hint string.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, 80))
        # We can't directly get TTL from a TCP socket easily across platforms,
        # so fall back to a heuristic using the socket option if available.
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        sock.close()

        if ttl <= 64:
            return "Linux/Unix (TTL-based)"
        elif ttl <= 128:
            return "Windows (TTL-based)"
        else:
            return "Network Device (TTL-based)"
    except OSError:
        return "Unknown"
