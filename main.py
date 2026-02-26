"""
Ghost Network Mapper — CLI Entry Point
========================================
Argparse-based command-line interface that orchestrates network scanning,
risk analysis, visualisation, and report generation.

Author: [Your Name]
Date: 2026-02-26

⚠️ DISCLAIMER:
Ghost Network Mapper is intended strictly for educational purposes and
authorized network testing only. Never run this tool on networks you do
not own or have explicit written permission to scan. Unauthorized network
scanning may be illegal in your jurisdiction.
"""

import argparse
import os
import subprocess
import sys
import time
from typing import Dict

from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from utils import (
    ETHICS_DISCLAIMER,
    format_duration,
    get_local_subnet,
    load_risky_ports,
    setup_logger,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERSION: str = "1.0.0"
BANNER: str = r"""
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
  ██║  ███╗███████║██║   ██║███████╗   ██║
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
  ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝
  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗
  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
  ███╗   ███╗ █████╗ ██████╗ ██████╗ ███████╗██████╗
  ████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ██╔████╔██║███████║██████╔╝██████╔╝█████╗  ██████╔╝
  ██║╚██╔╝██║██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
  ██║ ╚═╝ ██║██║  ██║██║     ██║     ███████╗██║  ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
"""

DEFAULT_OUTPUT_DIR: str = "./outputs"
DEFAULT_PORT_RANGE: str = "1-1024"
FULL_PORT_RANGE: str = "1-65535"
DEFAULT_TIMEOUT: int = 120

console = Console()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the CLI.

    Returns:
        Configured ``argparse.ArgumentParser``.
    """
    parser = argparse.ArgumentParser(
        prog="ghost-network-mapper",
        description=(
            "Ghost Network Mapper — Intelligent Network Reconnaissance "
            "& Visualization Tool"
        ),
        epilog=ETHICS_DISCLAIMER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--subnet",
        type=str,
        default=None,
        help="Target subnet in CIDR notation (default: auto-detect).",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default=DEFAULT_PORT_RANGE,
        help='Port range to scan. Use "full" for 1-65535 (default: 1-1024).',
    )
    parser.add_argument(
        "--output",
        type=str,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR}).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Scan timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the Streamlit GUI instead of running a CLI scan.",
    )
    parser.add_argument(
        "--no-pdf",
        action="store_true",
        help="Skip PDF report generation.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose / debug-level logging.",
    )

    return parser


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def main() -> None:
    """Execute the Ghost Network Mapper CLI pipeline."""
    parser = build_parser()
    args = parser.parse_args()

    # ── Launch GUI mode ──────────────────────────────────────────────
    if args.gui:
        gui_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "gui", "streamlit_app.py"
        )
        if not os.path.isfile(gui_path):
            console.print("[red]Streamlit app not found.[/]")
            sys.exit(1)
        console.print("[cyan]Launching Streamlit dashboard…[/]")
        subprocess.run([sys.executable, "-m", "streamlit", "run", gui_path], check=False)
        return

    # ── CLI mode ─────────────────────────────────────────────────────
    # Banner
    console.print(BANNER, style="bold cyan")
    console.print(f"  v{VERSION}", style="bold white")
    console.print()

    # Ethics disclaimer
    console.print(
        Panel(
            ETHICS_DISCLAIMER,
            title="⚠️  Disclaimer",
            border_style="yellow",
            padding=(1, 2),
        )
    )

    # Setup
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, "logs")

    logger = setup_logger(log_path)
    if args.verbose:
        for handler in logger.handlers:
            handler.setLevel("DEBUG")

    # Subnet
    subnet = args.subnet or get_local_subnet()
    port_range = FULL_PORT_RANGE if args.ports.lower() == "full" else args.ports

    # Config summary
    console.print(
        Panel(
            f"[bold]Subnet:[/]  {subnet}\n"
            f"[bold]Ports:[/]   {port_range}\n"
            f"[bold]Timeout:[/] {args.timeout}s\n"
            f"[bold]Output:[/]  {output_dir}",
            title="🔧 Scan Configuration",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    start_time = time.time()

    try:
        # ── 1. Scanner ──────────────────────────────────────────────
        from scanner import NetworkScanner

        scanner = NetworkScanner(
            subnet=subnet,
            port_range=port_range,
            timeout=args.timeout,
            logger=logger,
        )
        hosts = scanner.run()

        if not hosts:
            console.print(
                "[yellow]No hosts discovered. Check subnet or permissions.[/]"
            )
            logger.warning("Scan completed with 0 hosts discovered.")
            return

        # ── 2. Analyzer ─────────────────────────────────────────────
        from analyzer import RiskAnalyzer

        risky_ports = load_risky_ports()
        analyzer = RiskAnalyzer(risky_ports=risky_ports, logger=logger)
        hosts = analyzer.analyze(hosts)
        summary = analyzer.generate_summary(hosts)

        # ── 3. Visualizer ────────────────────────────────────────────
        from visualizer import NetworkVisualizer

        visualizer = NetworkVisualizer(output_dir=output_dir, logger=logger)
        graph_paths: Dict[str, str] = {}
        graph_paths["topology"] = visualizer.build_topology_graph(hosts)
        graph_paths["port_chart"] = visualizer.build_port_chart(hosts)
        graph_paths["risk_pie"] = visualizer.build_risk_pie(summary)

        # ── 4. Report Generator ──────────────────────────────────────
        from report_generator import ReportGenerator

        reporter = ReportGenerator(output_dir=output_dir, logger=logger)
        json_path = reporter.export_json(hosts, summary)
        csv_path = reporter.export_csv(hosts)
        html_path = reporter.export_html(hosts, summary, graph_paths)

        pdf_path = None
        if not args.no_pdf:
            pdf_path = reporter.export_pdf(html_path)

        # ── Console summary table ────────────────────────────────────
        table = Table(
            title="👻 Scan Results",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("IP Address", style="cyan", no_wrap=True)
        table.add_column("Hostname")
        table.add_column("OS")
        table.add_column("Open Ports", justify="center")
        table.add_column("Risk Level", justify="center")

        risk_style_map = {
            "HIGH": "bold red",
            "MEDIUM": "bold yellow",
            "LOW": "bold green",
            "NONE": "dim",
        }

        for host in hosts:
            risk = host.get("overall_risk", "NONE")
            style = risk_style_map.get(risk, "dim")
            table.add_row(
                host.get("ip", ""),
                host.get("hostname", "N/A"),
                host.get("os_guess", "Unknown"),
                str(len(host.get("open_ports", []))),
                f"[{style}]{risk}[/{style}]",
            )

        console.print()
        console.print(table)
        console.print()

        # ── Output file paths ────────────────────────────────────────
        console.print(
            Panel(
                "\n".join(
                    filter(
                        None,
                        [
                            f"📄 JSON  → {json_path}",
                            f"📊 CSV   → {csv_path}",
                            f"🌐 HTML  → {html_path}",
                            f"📕 PDF   → {pdf_path}" if pdf_path else None,
                            f"🗺️  Topo  → {graph_paths.get('topology', 'N/A')}",
                            f"📈 Ports → {graph_paths.get('port_chart', 'N/A')}",
                            f"🎯 Risk  → {graph_paths.get('risk_pie', 'N/A')}",
                        ],
                    )
                ),
                title="📁 Output Files",
                border_style="green",
                padding=(1, 2),
            )
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]⏹  Scan interrupted by user.[/]")
        logger.warning("Scan interrupted by user (KeyboardInterrupt).")
        sys.exit(130)
    except RuntimeError as exc:
        console.print(f"\n[red]❌ Error: {exc}[/]")
        logger.error("Runtime error: %s", exc)
        sys.exit(1)

    elapsed = time.time() - start_time
    logger.info("Total execution time: %s", format_duration(elapsed))
    console.print(
        f"\n[bold green]✅ Scan complete in {format_duration(elapsed)}[/bold green]"
    )


if __name__ == "__main__":
    main()
