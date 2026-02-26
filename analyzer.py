"""
Ghost Network Mapper — Risk Analysis Engine
=============================================
Evaluates discovered hosts and their open ports against a knowledge base of
risky services, assigns risk levels, provides vulnerability hints and
remediation recommendations.

Author: [Your Name]
Date: 2026-02-26
"""

from datetime import datetime
from typing import Any, Dict, List, Set

# ---------------------------------------------------------------------------
# Constants — Risk classification sets
# ---------------------------------------------------------------------------
HIGH_RISK_PORTS: Set[int] = {21, 23, 445, 3389, 5900, 6379, 27017, 1433, 3306}
MEDIUM_RISK_PORTS: Set[int] = {22, 25, 53, 80, 110, 139, 143, 8080, 8443, 5432, 1521}

# Vulnerability hints keyed by port number
VULNERABILITY_HINTS: Dict[int, str] = {
    21: "FTP allows plaintext credential transmission. Upgrade to SFTP/FTPS.",
    22: "SSH is a common brute-force target. Enforce key-based auth & fail2ban.",
    23: "Telnet transmits everything in cleartext — disable immediately. Use SSH.",
    25: "Open SMTP relay can be abused for spam. Restrict relay access.",
    53: "Open DNS resolver may be abused for amplification DDoS attacks.",
    80: "HTTP traffic is unencrypted. Enforce HTTPS with TLS 1.2+.",
    110: "POP3 sends credentials in plaintext. Use POP3S (port 995).",
    135: "MS-RPC endpoint mapper — used in lateral movement (e.g., PsExec).",
    139: "NetBIOS Session Service — SMB enumeration vector. Block at firewall.",
    143: "IMAP plaintext auth. Migrate to IMAPS (port 993).",
    443: "HTTPS — verify TLS version ≥ 1.2 and strong cipher suites.",
    445: "CVE-2017-0144 (EternalBlue) — patch MS17-010 immediately. "
         "Block SMBv1. High-priority ransomware vector.",
    1433: "MSSQL exposed — risk of SQL injection & credential brute-force. "
          "Restrict to trusted IPs only.",
    1521: "Oracle DB listener exposed — restrict network access.",
    3306: "MySQL exposed — enforce strong auth & restrict bind address to localhost.",
    3389: "RDP exposed — CVE-2019-0708 (BlueKeep). Enable NLA, use a VPN gateway.",
    5432: "PostgreSQL exposed — enforce pg_hba.conf restrictions & strong passwords.",
    5900: "VNC typically lacks strong auth. Tunnel via SSH or VPN.",
    6379: "Redis often runs without authentication. Set requirepass immediately.",
    8080: "Dev/proxy HTTP server exposed — ensure it is not a forgotten dev instance.",
    8443: "HTTPS-alt — verify certificate validity and TLS configuration.",
    27017: "MongoDB — unauthenticated access is the default. Enable auth & bind to localhost.",
}

# Per-port recommendations (more actionable)
PORT_RECOMMENDATIONS: Dict[int, str] = {
    21: "Disable FTP or replace with SFTP. If FTP is required, enforce TLS (FTPS).",
    22: "Disable password authentication; use SSH key pairs. Deploy fail2ban.",
    23: "Disable Telnet entirely and replace with SSH.",
    25: "Configure SMTP authentication and restrict relay to authorised senders.",
    53: "Rate-limit DNS responses and disable recursion for external queries.",
    80: "Redirect all HTTP to HTTPS. Deploy HSTS headers.",
    110: "Migrate to POP3S or replace with IMAP over TLS.",
    135: "Block port 135 at the perimeter firewall.",
    139: "Disable NetBIOS over TCP/IP or restrict to internal VLAN.",
    143: "Migrate to IMAPS (port 993) for encrypted email retrieval.",
    443: "Audit TLS certificates and disable TLS 1.0/1.1. Enable HSTS.",
    445: "Disable SMBv1, apply MS17-010 patch, and restrict SMB to internal networks.",
    1433: "Bind MSSQL to localhost or trusted IPs. Enforce strong SA password.",
    1521: "Use Oracle Net encryption and restrict listener to known hosts.",
    3306: "Bind MySQL to 127.0.0.1 and use TLS for remote connections.",
    3389: "Enable Network Level Authentication (NLA). Restrict RDP via VPN.",
    5432: "Configure pg_hba.conf to reject non-local connections without TLS.",
    5900: "Tunnel VNC through SSH or a VPN. Set a strong VNC password.",
    6379: "Set a requirepass directive in redis.conf and bind to 127.0.0.1.",
    8080: "If not needed, shut down the service. Otherwise, enforce authentication.",
    8443: "Validate TLS certificate and cipher suite configuration.",
    27017: "Enable MongoDB authentication and bind to 127.0.0.1.",
}


class RiskAnalyzer:
    """Evaluates open-port findings and assigns risk levels with recommendations.

    Attributes:
        risky_ports: Mapping of port → description for known-risky services.
        logger: Configured ``logging.Logger`` instance.
    """

    def __init__(self, risky_ports: Dict[int, str], logger: Any = None) -> None:
        """Initialise the analyser.

        Args:
            risky_ports: Dict from ``utils.load_risky_ports()``.
            logger: A ``logging.Logger`` instance.
        """
        self.risky_ports: Dict[int, str] = risky_ports
        self.logger = logger

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    def analyze(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyse every host's open ports and enrich with risk metadata.

        For each host the method adds:
        - Per-port ``risk_level`` (HIGH / MEDIUM / LOW).
        - ``overall_risk`` — highest risk across all open ports (or NONE).
        - ``vulnerability_hints`` — list of CVE / attack descriptions.
        - ``recommendations`` — actionable remediation steps.

        Args:
            hosts: List of host dicts (must include ``open_ports``).

        Returns:
            The same list, enriched in-place and returned for convenience.
        """
        if self.logger:
            self.logger.info("Analysing risk for [cyan]%d hosts[/]…", len(hosts))

        for host in hosts:
            open_ports: List[Dict[str, Any]] = host.get("open_ports", [])
            vuln_hints: List[str] = []
            recommendations: List[str] = []
            risk_levels_found: List[str] = []

            for port_entry in open_ports:
                port_num: int = port_entry["port"]
                risk = self._classify_port(port_num)
                port_entry["risk_level"] = risk
                risk_levels_found.append(risk)

                # Vulnerability hint
                if port_num in VULNERABILITY_HINTS:
                    hint = f"Port {port_num}: {VULNERABILITY_HINTS[port_num]}"
                    vuln_hints.append(hint)

                # Recommendation
                if port_num in PORT_RECOMMENDATIONS:
                    rec = f"Port {port_num}: {PORT_RECOMMENDATIONS[port_num]}"
                    if rec not in recommendations:
                        recommendations.append(rec)

            # Overall host risk
            host["overall_risk"] = self._highest_risk(risk_levels_found)
            host["vulnerability_hints"] = vuln_hints
            host["recommendations"] = recommendations

        if self.logger:
            high = sum(1 for h in hosts if h.get("overall_risk") == "HIGH")
            med = sum(1 for h in hosts if h.get("overall_risk") == "MEDIUM")
            low = sum(1 for h in hosts if h.get("overall_risk") == "LOW")
            self.logger.info(
                "Risk analysis complete — HIGH: %d | MEDIUM: %d | LOW: %d",
                high,
                med,
                low,
            )

        return hosts

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    def generate_summary(self, analyzed_hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Produce an executive summary of the scan results.

        Args:
            analyzed_hosts: Hosts list after ``analyze()`` has been called.

        Returns:
            Summary dict with aggregate statistics.
        """
        total = len(analyzed_hosts)
        high = sum(1 for h in analyzed_hosts if h.get("overall_risk") == "HIGH")
        medium = sum(1 for h in analyzed_hosts if h.get("overall_risk") == "MEDIUM")
        low = sum(1 for h in analyzed_hosts if h.get("overall_risk") == "LOW")
        total_ports = sum(len(h.get("open_ports", [])) for h in analyzed_hosts)

        # Most exposed host
        most_exposed = max(
            analyzed_hosts,
            key=lambda h: len(h.get("open_ports", [])),
            default={},
        )
        most_exposed_ip = most_exposed.get("ip", "N/A")

        # Top risky ports across all hosts
        port_freq: Dict[int, int] = {}
        for host in analyzed_hosts:
            for p in host.get("open_ports", []):
                pn = p["port"]
                if pn in self.risky_ports:
                    port_freq[pn] = port_freq.get(pn, 0) + 1
        top_risky = sorted(port_freq, key=port_freq.get, reverse=True)[:10]  # type: ignore[arg-type]

        return {
            "total_hosts": total,
            "high_risk_count": high,
            "medium_risk_count": medium,
            "low_risk_count": low,
            "total_open_ports": total_ports,
            "most_exposed_host": most_exposed_ip,
            "top_risky_ports": top_risky,
            "scan_timestamp": datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _classify_port(port: int) -> str:
        """Return the risk level for a given port number.

        Args:
            port: Port number.

        Returns:
            ``"HIGH"``, ``"MEDIUM"``, or ``"LOW"``.
        """
        if port in HIGH_RISK_PORTS:
            return "HIGH"
        if port in MEDIUM_RISK_PORTS:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _highest_risk(levels: List[str]) -> str:
        """Return the highest risk level from a list.

        Args:
            levels: List of risk level strings.

        Returns:
            Highest risk found, or ``"NONE"`` if list is empty.
        """
        if not levels:
            return "NONE"
        priority = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return max(levels, key=lambda l: priority.get(l, 0))
