"""
Ghost Network Mapper — Report Generator Module
================================================
Exports scan results and analysis to professional HTML, JSON, CSV, and PDF
reports suitable for stakeholder review.

Author: [Your Name]
Date: 2026-02-26
"""

import base64
import csv
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd

from utils import ETHICS_DISCLAIMER

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPORTS_DIR_NAME: str = "reports"
CSS_ASSET_PATH: str = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "assets", "style.css"
)


class ReportGenerator:
    """Exports scan results to multiple formats (JSON, CSV, HTML, PDF).

    Attributes:
        output_dir: Root output directory.
        reports_dir: Directory where report files are written.
        logger: Configured ``logging.Logger`` instance.
    """

    def __init__(self, output_dir: str, logger: Any = None) -> None:
        """Initialise the report generator.

        Args:
            output_dir: Root output directory (``outputs/``).
            logger: A ``logging.Logger`` instance.
        """
        self.reports_dir: str = os.path.join(output_dir, REPORTS_DIR_NAME)
        os.makedirs(self.reports_dir, exist_ok=True)
        self.logger = logger

    # ------------------------------------------------------------------
    # JSON export
    # ------------------------------------------------------------------
    def export_json(
        self, hosts: List[Dict[str, Any]], summary: Dict[str, Any]
    ) -> str:
        """Save the full scan data as pretty-printed JSON.

        Args:
            hosts: Enriched host list.
            summary: Summary dict from the analyser.

        Returns:
            Absolute path to the saved JSON file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.reports_dir, f"scan_{timestamp}.json")

        payload = {
            "scan_summary": summary,
            "hosts": hosts,
            "disclaimer": ETHICS_DISCLAIMER,
        }

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)

        if self.logger:
            self.logger.info("JSON report saved → [green]%s[/]", filepath)
        return os.path.abspath(filepath)

    # ------------------------------------------------------------------
    # CSV export
    # ------------------------------------------------------------------
    def export_csv(self, hosts: List[Dict[str, Any]]) -> str:
        """Flatten host + port data into a CSV file.

        Columns: ip, hostname, mac, vendor, os_guess, overall_risk,
        port, protocol, service, version, port_risk, vuln_hint.

        Args:
            hosts: Enriched host list.

        Returns:
            Absolute path to the saved CSV file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.reports_dir, f"scan_{timestamp}.csv")

        rows: List[Dict[str, Any]] = []
        for host in hosts:
            base = {
                "ip": host.get("ip", ""),
                "hostname": host.get("hostname", ""),
                "mac": host.get("mac", ""),
                "vendor": host.get("vendor", ""),
                "os_guess": host.get("os_guess", ""),
                "overall_risk": host.get("overall_risk", "NONE"),
            }
            open_ports = host.get("open_ports", [])
            if open_ports:
                for p in open_ports:
                    row = dict(base)
                    row["port"] = p.get("port", "")
                    row["protocol"] = p.get("protocol", "")
                    row["service"] = p.get("service", "")
                    row["version"] = p.get("version", "")
                    row["port_risk"] = p.get("risk_level", "LOW")
                    row["vuln_hint"] = ""
                    # Find matching hint
                    for hint in host.get("vulnerability_hints", []):
                        if hint.startswith(f"Port {p.get('port', '')}:"):
                            row["vuln_hint"] = hint
                            break
                    rows.append(row)
            else:
                row = dict(base)
                row.update({
                    "port": "",
                    "protocol": "",
                    "service": "",
                    "version": "",
                    "port_risk": "",
                    "vuln_hint": "",
                })
                rows.append(row)

        df = pd.DataFrame(rows)
        df.to_csv(filepath, index=False, quoting=csv.QUOTE_ALL)

        if self.logger:
            self.logger.info("CSV report saved → [green]%s[/]", filepath)
        return os.path.abspath(filepath)

    # ------------------------------------------------------------------
    # HTML export
    # ------------------------------------------------------------------
    def export_html(
        self,
        hosts: List[Dict[str, Any]],
        summary: Dict[str, Any],
        graph_paths: Dict[str, str],
    ) -> str:
        """Generate a self-contained, dark-themed professional HTML report.

        Includes executive summary cards, inline topology PNG, embedded Plotly
        charts, an expandable device table, recommendations, and a disclaimer
        footer.

        Args:
            hosts: Enriched host list.
            summary: Summary dict from the analyser.
            graph_paths: Dict with keys ``topology``, ``port_chart``,
                ``risk_pie`` mapping to file paths.

        Returns:
            Absolute path to the saved HTML file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.reports_dir, f"scan_{timestamp}.html")

        # Read CSS
        css = ""
        if os.path.isfile(CSS_ASSET_PATH):
            with open(CSS_ASSET_PATH, "r", encoding="utf-8") as fh:
                css = fh.read()

        # Encode topology PNG as base64
        topology_img_tag = ""
        topo_path = graph_paths.get("topology", "")
        if topo_path and os.path.isfile(topo_path):
            with open(topo_path, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode("ascii")
            topology_img_tag = (
                f'<img src="data:image/png;base64,{b64}" '
                f'alt="Network Topology" />'
            )

        # Read Plotly chart HTML for inline embedding
        port_chart_html = self._read_chart_file(graph_paths.get("port_chart", ""))
        risk_pie_html = self._read_chart_file(graph_paths.get("risk_pie", ""))

        # Build device table rows
        device_rows = self._build_device_rows(hosts)

        # Build recommendations
        all_recs = self._collect_recommendations(hosts)
        rec_items = "\n".join(
            f'<li class="{"critical" if "immediately" in r.lower() else ""}">'
            f'<span class="rec-icon">🔧</span>{_html_escape(r)}</li>'
            for r in all_recs
        )

        scan_ts = summary.get("scan_timestamp", datetime.now().isoformat())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Ghost Network Mapper — Scan Report</title>
<style>
{css}
</style>
</head>
<body>
<div class="report-container">

<!-- Header -->
<div class="report-header">
    <h1><span class="ghost-icon">👻</span> Ghost Network Mapper</h1>
    <p class="tagline">Map your network. Know your exposure. Secure your perimeter.</p>
    <p class="scan-meta">
        <span>📅 {scan_ts}</span>
        <span>🖥️ {summary.get('total_hosts', 0)} hosts discovered</span>
        <span>🔓 {summary.get('total_open_ports', 0)} open ports</span>
    </p>
</div>

<!-- Executive Summary -->
<h2 class="section-title">📊 Executive Summary</h2>
<div class="metrics-grid">
    <div class="metric-card">
        <div class="metric-value total">{summary.get('total_hosts', 0)}</div>
        <div class="metric-label">Total Hosts</div>
    </div>
    <div class="metric-card">
        <div class="metric-value high">{summary.get('high_risk_count', 0)}</div>
        <div class="metric-label">High Risk</div>
    </div>
    <div class="metric-card">
        <div class="metric-value medium">{summary.get('medium_risk_count', 0)}</div>
        <div class="metric-label">Medium Risk</div>
    </div>
    <div class="metric-card">
        <div class="metric-value low">{summary.get('low_risk_count', 0)}</div>
        <div class="metric-label">Low Risk</div>
    </div>
    <div class="metric-card">
        <div class="metric-value total">{summary.get('total_open_ports', 0)}</div>
        <div class="metric-label">Open Ports</div>
    </div>
</div>

<!-- Most Exposed Host -->
<div class="exposed-host-section">
    <div class="exposed-host-card">
        <div class="exposed-host-label">🎯 Most Exposed Host</div>
        <div class="exposed-host-ip">{_html_escape(str(summary.get('most_exposed_host', 'N/A')))}</div>
    </div>
</div>

<!-- Topology -->
<h2 class="section-title">🗺️ Network Topology</h2>
<div class="topology-section">
    {topology_img_tag if topology_img_tag else '<p style="color:#8b949e;">Topology graph not available.</p>'}
</div>

<!-- Port Distribution -->
<h2 class="section-title">📈 Port Distribution</h2>
<div class="chart-container">
    {port_chart_html if port_chart_html else '<p style="padding:20px;color:#8b949e;">Chart not available.</p>'}
</div>

<!-- Risk Distribution -->
<h2 class="section-title">🎯 Risk Distribution</h2>
<div class="chart-container">
    {risk_pie_html if risk_pie_html else '<p style="padding:20px;color:#8b949e;">Chart not available.</p>'}
</div>

<!-- Device Details -->
<h2 class="section-title">💻 Discovered Devices</h2>
<table class="device-table">
<thead>
<tr>
    <th>IP Address</th>
    <th>Hostname</th>
    <th>MAC</th>
    <th>Vendor</th>
    <th>OS</th>
    <th>Open Ports</th>
    <th>Risk</th>
    <th>Details</th>
</tr>
</thead>
<tbody>
{device_rows}
</tbody>
</table>

<!-- Recommendations -->
<h2 class="section-title">🔐 Recommendations</h2>
<ul class="recommendations-list">
{rec_items if rec_items else '<li>No specific recommendations — network appears clean.</li>'}
</ul>

<!-- Footer -->
<div class="report-footer">
    <p>Generated by <strong>Ghost Network Mapper</strong></p>
    <p class="disclaimer">⚠️ {_html_escape(ETHICS_DISCLAIMER)}</p>
    <p>Report generated at {scan_ts}</p>
</div>

</div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(html)

        if self.logger:
            self.logger.info("HTML report saved → [green]%s[/]", filepath)
        return os.path.abspath(filepath)

    # ------------------------------------------------------------------
    # PDF export
    # ------------------------------------------------------------------
    def export_pdf(self, html_path: str) -> Optional[str]:
        """Convert the HTML report to PDF using WeasyPrint.

        Falls back gracefully if WeasyPrint is not installed.

        Args:
            html_path: Path to the HTML report file.

        Returns:
            Absolute path to the PDF file, or ``None`` if generation failed.
        """
        try:
            from weasyprint import HTML as WeasyprintHTML  # type: ignore[import-untyped]
        except ImportError:
            if self.logger:
                self.logger.warning(
                    "weasyprint not installed — skipping PDF generation. "
                    "Install with: pip install weasyprint"
                )
            return None

        pdf_path = html_path.replace(".html", ".pdf")

        try:
            WeasyprintHTML(filename=html_path).write_pdf(pdf_path)
            if self.logger:
                self.logger.info("PDF report saved → [green]%s[/]", pdf_path)
            return os.path.abspath(pdf_path)
        except Exception as exc:
            if self.logger:
                self.logger.error("PDF generation failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _build_device_rows(self, hosts: List[Dict[str, Any]]) -> str:
        """Build HTML table rows for each host with expandable port details.

        Args:
            hosts: Enriched host list.

        Returns:
            HTML string of ``<tr>`` elements.
        """
        rows: List[str] = []
        for idx, host in enumerate(hosts):
            ip = _html_escape(host.get("ip", ""))
            hostname = _html_escape(host.get("hostname", "N/A"))
            mac = _html_escape(host.get("mac", "N/A"))
            vendor = _html_escape(host.get("vendor", "Unknown"))
            os_guess = _html_escape(host.get("os_guess", "Unknown"))
            risk = host.get("overall_risk", "NONE")
            open_ports = host.get("open_ports", [])

            risk_badge = f'<span class="risk-badge {risk.lower()}">{risk}</span>'

            # Accordion for port details
            accordion_id = f"acc_{idx}"
            port_details = ""
            if open_ports:
                port_rows = ""
                for p in open_ports:
                    p_risk = p.get("risk_level", "LOW")
                    port_rows += (
                        f"<tr>"
                        f"<td>{p.get('port', '')}</td>"
                        f"<td>{_html_escape(p.get('protocol', ''))}</td>"
                        f"<td>{_html_escape(p.get('service', ''))}</td>"
                        f"<td>{_html_escape(p.get('version', ''))}</td>"
                        f'<td><span class="risk-badge {p_risk.lower()}">{p_risk}</span></td>'
                        f"<td>{_html_escape(p.get('banner', '')[:60])}</td>"
                        f"</tr>"
                    )

                port_details = (
                    f'<input type="checkbox" id="{accordion_id}" class="accordion-toggle"/>'
                    f'<label for="{accordion_id}" class="accordion-label">Show {len(open_ports)} port(s)</label>'
                    f'<div class="accordion-content">'
                    f'<table class="port-table">'
                    f"<tr><th>Port</th><th>Proto</th><th>Service</th>"
                    f"<th>Version</th><th>Risk</th><th>Banner</th></tr>"
                    f"{port_rows}</table></div>"
                )
            else:
                port_details = '<span style="color:#6e7681;">No open ports</span>'

            rows.append(
                f"<tr>"
                f'<td class="ip-cell">{ip}</td>'
                f"<td>{hostname}</td>"
                f'<td class="mac-cell">{mac}</td>'
                f"<td>{vendor}</td>"
                f"<td>{os_guess}</td>"
                f"<td>{len(open_ports)}</td>"
                f"<td>{risk_badge}</td>"
                f"<td>{port_details}</td>"
                f"</tr>"
            )

        return "\n".join(rows)

    @staticmethod
    def _read_chart_file(filepath: str) -> str:
        """Read a Plotly HTML chart and extract the body content.

        Args:
            filepath: Path to a Plotly-generated HTML file.

        Returns:
            Inner HTML content string, or empty string on failure.
        """
        if not filepath or not os.path.isfile(filepath):
            return ""
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                content = fh.read()
            # Extract body content for embedding
            start = content.find("<body>")
            end = content.find("</body>")
            if start != -1 and end != -1:
                return content[start + 6:end]
            return content
        except OSError:
            return ""

    @staticmethod
    def _collect_recommendations(hosts: List[Dict[str, Any]]) -> List[str]:
        """Collect unique recommendations across all hosts.

        Args:
            hosts: Enriched host list.

        Returns:
            De-duplicated list of recommendation strings.
        """
        seen: set = set()
        recs: List[str] = []
        for host in hosts:
            for rec in host.get("recommendations", []):
                if rec not in seen:
                    seen.add(rec)
                    recs.append(rec)
        return recs


def _html_escape(text: str) -> str:
    """Escape special HTML characters in a string.

    Args:
        text: Raw string.

    Returns:
        HTML-safe string.
    """
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
