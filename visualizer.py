"""
Ghost Network Mapper — Network Visualizer Module
==================================================
Generates network topology graphs, port distribution charts, and risk
distribution pie charts from scan results.

Author: [Your Name]
Date: 2026-02-26
"""

import os
from datetime import datetime
from typing import Any, Dict, List

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import networkx as nx
import plotly.graph_objects as go

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RISK_COLORS: Dict[str, str] = {
    "HIGH": "#f85149",
    "MEDIUM": "#d29922",
    "LOW": "#3fb950",
    "NONE": "#6e7681",
}

DARK_BG: str = "#1a1a2e"
DARK_PAPER: str = "#16213e"
DARK_FONT_COLOR: str = "#e6edf3"


class NetworkVisualizer:
    """Renders network topology graphs and interactive charts from scan data.

    Attributes:
        output_dir: Root directory for saving generated graph files.
        logger: Configured ``logging.Logger`` instance.
    """

    def __init__(self, output_dir: str, logger: Any = None) -> None:
        """Initialise the visualiser.

        Args:
            output_dir: Root output directory (``outputs/``).
            logger: A ``logging.Logger`` instance.
        """
        self.graphs_dir: str = os.path.join(output_dir, "graphs")
        os.makedirs(self.graphs_dir, exist_ok=True)
        self.logger = logger

    # ------------------------------------------------------------------
    # Topology graph (Matplotlib + NetworkX)
    # ------------------------------------------------------------------
    def build_topology_graph(self, hosts: List[Dict[str, Any]]) -> str:
        """Build and render a network topology PNG.

        A central **Gateway** node is connected to every discovered host.
        Node colour indicates risk level; node size is proportional to the
        number of open ports.

        Args:
            hosts: Enriched host list from the analyser.

        Returns:
            Absolute path to the saved PNG file.
        """
        if self.logger:
            self.logger.info("Building network topology graph…")

        G = nx.Graph()
        G.add_node("Gateway", risk="NONE", ports=0)

        node_colors: List[str] = [RISK_COLORS["NONE"]]  # Gateway color
        node_sizes: List[int] = [800]  # Gateway size
        labels: Dict[str, str] = {"Gateway": "🌐 Gateway"}

        for host in hosts:
            ip = host["ip"]
            risk = host.get("overall_risk", "NONE")
            num_ports = len(host.get("open_ports", []))

            G.add_node(ip, risk=risk, ports=num_ports)
            G.add_edge("Gateway", ip)

            node_colors.append(RISK_COLORS.get(risk, RISK_COLORS["NONE"]))
            node_sizes.append(max(300, 300 + num_ports * 80))

            # Label: IP + truncated hostname
            hostname = host.get("hostname", "N/A")
            if hostname and hostname != "N/A":
                label = f"{ip}\n{hostname[:15]}"
            else:
                label = ip
            labels[ip] = label

        # Layout and draw
        fig, ax = plt.subplots(figsize=(14, 10))
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#0d1117")

        pos = nx.spring_layout(G, k=2.5, iterations=50, seed=42)

        nx.draw_networkx_edges(
            G, pos, ax=ax, edge_color="#30363d", width=1.5, alpha=0.7
        )
        nx.draw_networkx_nodes(
            G, pos, ax=ax, node_color=node_colors, node_size=node_sizes,
            edgecolors="#e6edf3", linewidths=1.2, alpha=0.92,
        )
        nx.draw_networkx_labels(
            G, pos, labels, ax=ax, font_size=8, font_color="#e6edf3",
            font_family="monospace",
        )

        # Legend
        for label_text, color in RISK_COLORS.items():
            ax.scatter([], [], c=color, s=80, label=label_text)
        ax.legend(
            loc="upper left", fontsize=9, framealpha=0.3,
            facecolor="#161b22", edgecolor="#30363d", labelcolor="#e6edf3",
        )

        ax.set_title(
            "Ghost Network Mapper — Topology",
            fontsize=16, fontweight="bold", color="#e6edf3", pad=20,
        )
        ax.axis("off")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.graphs_dir, f"topology_{timestamp}.png")
        fig.savefig(filepath, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)

        if self.logger:
            self.logger.info("Topology graph saved → [green]%s[/]", filepath)
        return os.path.abspath(filepath)

    # ------------------------------------------------------------------
    # Port distribution chart (Plotly)
    # ------------------------------------------------------------------
    def build_port_chart(self, hosts: List[Dict[str, Any]]) -> str:
        """Create a horizontal bar chart of the top 15 most common open ports.

        Bars are coloured by risk level.

        Args:
            hosts: Enriched host list from the analyser.

        Returns:
            Absolute path to the saved interactive HTML file.
        """
        if self.logger:
            self.logger.info("Building port distribution chart…")

        # Aggregate port counts
        port_data: Dict[int, Dict[str, Any]] = {}
        for host in hosts:
            for p in host.get("open_ports", []):
                pn = p["port"]
                if pn not in port_data:
                    port_data[pn] = {
                        "count": 0,
                        "service": p.get("service", "unknown"),
                        "risk": p.get("risk_level", "LOW"),
                    }
                port_data[pn]["count"] += 1

        # Sort and take top 15
        sorted_ports = sorted(port_data.items(), key=lambda x: x[1]["count"], reverse=True)[:15]
        sorted_ports.reverse()  # For horizontal bar (bottom = highest)

        ports_labels = [f"{p} ({d['service']})" for p, d in sorted_ports]
        counts = [d["count"] for _, d in sorted_ports]
        colors = [RISK_COLORS.get(d["risk"], RISK_COLORS["LOW"]) for _, d in sorted_ports]

        fig = go.Figure(
            go.Bar(
                x=counts,
                y=ports_labels,
                orientation="h",
                marker_color=colors,
                text=counts,
                textposition="outside",
                textfont=dict(color=DARK_FONT_COLOR),
            )
        )

        fig.update_layout(
            title=dict(text="Top Open Ports by Frequency", font=dict(size=18, color=DARK_FONT_COLOR)),
            xaxis=dict(title="Host Count", color=DARK_FONT_COLOR, gridcolor="#30363d"),
            yaxis=dict(color=DARK_FONT_COLOR),
            paper_bgcolor=DARK_PAPER,
            plot_bgcolor=DARK_BG,
            font=dict(family="Consolas, monospace", color=DARK_FONT_COLOR),
            margin=dict(l=180, r=40, t=60, b=40),
            height=max(400, len(sorted_ports) * 35 + 100),
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.graphs_dir, f"ports_{timestamp}.html")
        fig.write_html(filepath, include_plotlyjs="cdn")

        if self.logger:
            self.logger.info("Port chart saved → [green]%s[/]", filepath)
        return os.path.abspath(filepath)

    # ------------------------------------------------------------------
    # Risk pie / donut chart (Plotly)
    # ------------------------------------------------------------------
    def build_risk_pie(self, summary: Dict[str, Any]) -> str:
        """Create a donut chart showing risk distribution across hosts.

        Args:
            summary: Summary dict from ``RiskAnalyzer.generate_summary()``.

        Returns:
            Absolute path to the saved interactive HTML file.
        """
        if self.logger:
            self.logger.info("Building risk distribution chart…")

        labels = ["HIGH", "MEDIUM", "LOW", "NONE"]
        values = [
            summary.get("high_risk_count", 0),
            summary.get("medium_risk_count", 0),
            summary.get("low_risk_count", 0),
            max(0, summary.get("total_hosts", 0)
                - summary.get("high_risk_count", 0)
                - summary.get("medium_risk_count", 0)
                - summary.get("low_risk_count", 0)),
        ]
        colors = [RISK_COLORS[l] for l in labels]

        fig = go.Figure(
            go.Pie(
                labels=labels,
                values=values,
                hole=0.45,
                marker=dict(colors=colors, line=dict(color=DARK_BG, width=2)),
                textinfo="label+percent",
                textfont=dict(size=13, color=DARK_FONT_COLOR),
                hoverinfo="label+value+percent",
            )
        )

        fig.update_layout(
            title=dict(
                text="Host Risk Distribution",
                font=dict(size=18, color=DARK_FONT_COLOR),
            ),
            paper_bgcolor=DARK_BG,
            plot_bgcolor=DARK_BG,
            font=dict(family="Consolas, monospace", color=DARK_FONT_COLOR),
            legend=dict(font=dict(color=DARK_FONT_COLOR)),
            margin=dict(l=20, r=20, t=60, b=20),
            height=420,
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.graphs_dir, f"risk_pie_{timestamp}.html")
        fig.write_html(filepath, include_plotlyjs="cdn")

        if self.logger:
            self.logger.info("Risk pie chart saved → [green]%s[/]", filepath)
        return os.path.abspath(filepath)
