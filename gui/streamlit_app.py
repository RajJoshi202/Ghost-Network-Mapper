"""
Ghost Network Mapper — Streamlit GUI Dashboard
================================================
An optional web-based dashboard for running scans, viewing results, and
downloading reports interactively.

Author: [Your Name]
Date: 2026-02-26

⚠️ DISCLAIMER:
Ghost Network Mapper is intended strictly for educational purposes and
authorized network testing only. Never run this tool on networks you do
not own or have explicit written permission to scan. Unauthorized network
scanning may be illegal in your jurisdiction.
"""

import os
import sys

import streamlit as st

# Ensure the project root is importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from utils import (
    ETHICS_DISCLAIMER,
    get_local_subnet,
    load_risky_ports,
    setup_logger,
)

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Ghost Network Mapper",
    page_icon="👻",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark-themed custom CSS
st.markdown(
    """
    <style>
    .stApp {
        background-color: #0d1117;
        color: #e6edf3;
    }
    .stSidebar > div:first-child {
        background-color: #161b22;
    }
    .risk-high { color: #f85149; font-weight: bold; }
    .risk-medium { color: #d29922; font-weight: bold; }
    .risk-low { color: #3fb950; font-weight: bold; }
    .risk-none { color: #6e7681; }
    div[data-testid="metric-container"] {
        background-color: #1c2333;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 16px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
st.sidebar.title("👻 Ghost Network Mapper")
st.sidebar.markdown("---")

st.sidebar.warning(ETHICS_DISCLAIMER)

detected_subnet = get_local_subnet()
subnet_input = st.sidebar.text_input(
    "Target Subnet (CIDR)",
    value=detected_subnet,
    help="Enter the subnet to scan, e.g. 192.168.1.0/24",
)

port_option = st.sidebar.selectbox(
    "Port Range",
    options=["Common (1-1024)", "Full (1-65535)"],
    index=0,
)
port_range = "1-1024" if "Common" in port_option else "1-65535"

timeout_val = st.sidebar.slider("Scan Timeout (seconds)", 30, 600, 120, step=30)

scan_button = st.sidebar.button("🚀 Start Scan", type="primary", use_container_width=True)

st.sidebar.markdown("---")
st.sidebar.caption("v1.0.0 | Educational Use Only")

# ---------------------------------------------------------------------------
# Main area
# ---------------------------------------------------------------------------
st.title("👻 Ghost Network Mapper")
st.caption("Map your network. Know your exposure. Secure your perimeter.")

# Initialise session state
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None
if "summary" not in st.session_state:
    st.session_state.summary = None

# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------
if scan_button:
    output_dir = os.path.join(PROJECT_ROOT, "outputs")
    log_path = os.path.join(output_dir, "logs")
    os.makedirs(log_path, exist_ok=True)

    logger = setup_logger(log_path)

    with st.spinner("🔍 Discovering hosts and scanning ports — this may take a while…"):
        try:
            from scanner import NetworkScanner
            from analyzer import RiskAnalyzer
            from visualizer import NetworkVisualizer
            from report_generator import ReportGenerator

            # Scanner
            scanner = NetworkScanner(
                subnet=subnet_input,
                port_range=port_range,
                timeout=timeout_val,
                logger=logger,
            )
            hosts = scanner.run()

            if not hosts:
                st.warning("No hosts discovered. Check your subnet or run with elevated privileges.")
                st.stop()

            # Analyzer
            risky_ports = load_risky_ports()
            analyzer = RiskAnalyzer(risky_ports=risky_ports, logger=logger)
            hosts = analyzer.analyze(hosts)
            summary = analyzer.generate_summary(hosts)

            # Visualizer
            visualizer = NetworkVisualizer(output_dir=output_dir, logger=logger)
            topo_path = visualizer.build_topology_graph(hosts)
            port_chart_path = visualizer.build_port_chart(hosts)
            risk_pie_path = visualizer.build_risk_pie(summary)

            # Reporter
            reporter = ReportGenerator(output_dir=output_dir, logger=logger)
            json_path = reporter.export_json(hosts, summary)
            csv_path = reporter.export_csv(hosts)
            html_path = reporter.export_html(
                hosts, summary,
                {"topology": topo_path, "port_chart": port_chart_path, "risk_pie": risk_pie_path},
            )

            # Store in session
            st.session_state.scan_results = {
                "hosts": hosts,
                "summary": summary,
                "topo_path": topo_path,
                "port_chart_path": port_chart_path,
                "risk_pie_path": risk_pie_path,
                "json_path": json_path,
                "csv_path": csv_path,
                "html_path": html_path,
            }
            st.session_state.summary = summary

            st.success(f"✅ Scan complete — {len(hosts)} hosts discovered!")

        except RuntimeError as exc:
            st.error(f"❌ {exc}")
            st.stop()
        except Exception as exc:
            st.error(f"❌ Unexpected error: {exc}")
            logger.exception("Streamlit scan failed")
            st.stop()

# ---------------------------------------------------------------------------
# Display results
# ---------------------------------------------------------------------------
if st.session_state.scan_results is not None:
    data = st.session_state.scan_results
    hosts = data["hosts"]
    summary = data["summary"]

    # Metrics row
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Hosts", summary["total_hosts"])
    col2.metric("🔴 High Risk", summary["high_risk_count"])
    col3.metric("🟡 Medium Risk", summary["medium_risk_count"])
    col4.metric("🟢 Low Risk", summary["low_risk_count"])
    col5.metric("Open Ports", summary["total_open_ports"])

    st.markdown("---")

    # Tabs
    tab_devices, tab_viz, tab_reports = st.tabs(
        ["💻 Devices", "📊 Visualization", "📁 Reports"]
    )

    # ── Devices tab ──────────────────────────────────────────────────
    with tab_devices:
        import pandas as pd

        rows = []
        for h in hosts:
            rows.append({
                "IP": h.get("ip", ""),
                "Hostname": h.get("hostname", "N/A"),
                "MAC": h.get("mac", "N/A"),
                "Vendor": h.get("vendor", "Unknown"),
                "OS": h.get("os_guess", "Unknown"),
                "Open Ports": len(h.get("open_ports", [])),
                "Risk": h.get("overall_risk", "NONE"),
            })

        df = pd.DataFrame(rows)

        def _color_risk(val: str) -> str:
            colors = {
                "HIGH": "color: #f85149; font-weight: bold",
                "MEDIUM": "color: #d29922; font-weight: bold",
                "LOW": "color: #3fb950; font-weight: bold",
                "NONE": "color: #6e7681",
            }
            return colors.get(val, "")

        styled_df = df.style.map(_color_risk, subset=["Risk"])
        st.dataframe(styled_df, use_container_width=True, height=400)

        # Expandable details per host
        for h in hosts:
            with st.expander(f"🔍 {h['ip']} — {h.get('hostname', 'N/A')} [{h.get('overall_risk', 'NONE')}]"):
                if h.get("open_ports"):
                    port_df = pd.DataFrame(h["open_ports"])
                    st.dataframe(port_df, use_container_width=True)
                else:
                    st.info("No open ports detected.")

                if h.get("vulnerability_hints"):
                    st.warning("**Vulnerability Hints:**")
                    for hint in h["vulnerability_hints"]:
                        st.markdown(f"- {hint}")

                if h.get("recommendations"):
                    st.info("**Recommendations:**")
                    for rec in h["recommendations"]:
                        st.markdown(f"- {rec}")

    # ── Visualization tab ────────────────────────────────────────────
    with tab_viz:
        st.subheader("🗺️ Network Topology")
        topo_path = data.get("topo_path", "")
        if topo_path and os.path.isfile(topo_path):
            st.image(topo_path, use_container_width=True)
        else:
            st.info("Topology graph not available.")

        st.markdown("---")

        st.subheader("📈 Port Distribution")
        try:
            import plotly
            # Re-create chart objects for Plotly integration
            from visualizer import NetworkVisualizer as _NV, RISK_COLORS, DARK_BG, DARK_PAPER, DARK_FONT_COLOR
            import plotly.graph_objects as go

            # Aggregate port data
            port_data = {}
            for h in hosts:
                for p in h.get("open_ports", []):
                    pn = p["port"]
                    if pn not in port_data:
                        port_data[pn] = {"count": 0, "service": p.get("service", "unknown"), "risk": p.get("risk_level", "LOW")}
                    port_data[pn]["count"] += 1

            sorted_ports = sorted(port_data.items(), key=lambda x: x[1]["count"], reverse=True)[:15]
            sorted_ports.reverse()

            if sorted_ports:
                fig_ports = go.Figure(go.Bar(
                    x=[d["count"] for _, d in sorted_ports],
                    y=[f"{p} ({d['service']})" for p, d in sorted_ports],
                    orientation="h",
                    marker_color=[RISK_COLORS.get(d["risk"], RISK_COLORS["LOW"]) for _, d in sorted_ports],
                ))
                fig_ports.update_layout(
                    paper_bgcolor=DARK_PAPER, plot_bgcolor=DARK_BG,
                    font=dict(color=DARK_FONT_COLOR),
                    xaxis=dict(title="Host Count", gridcolor="#30363d"),
                    height=max(350, len(sorted_ports) * 30 + 100),
                )
                st.plotly_chart(fig_ports, use_container_width=True)
            else:
                st.info("No open ports to display.")
        except Exception as exc:
            st.warning(f"Could not render port chart: {exc}")

        st.markdown("---")

        st.subheader("🎯 Risk Distribution")
        try:
            labels = ["HIGH", "MEDIUM", "LOW", "NONE"]
            values = [
                summary["high_risk_count"],
                summary["medium_risk_count"],
                summary["low_risk_count"],
                max(0, summary["total_hosts"] - summary["high_risk_count"]
                    - summary["medium_risk_count"] - summary["low_risk_count"]),
            ]
            fig_pie = go.Figure(go.Pie(
                labels=labels, values=values, hole=0.45,
                marker=dict(colors=[RISK_COLORS[l] for l in labels]),
                textinfo="label+percent",
            ))
            fig_pie.update_layout(
                paper_bgcolor=DARK_BG, font=dict(color=DARK_FONT_COLOR), height=400,
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        except Exception as exc:
            st.warning(f"Could not render risk chart: {exc}")

    # ── Reports tab ──────────────────────────────────────────────────
    with tab_reports:
        st.subheader("📥 Download Reports")

        col_a, col_b, col_c = st.columns(3)

        json_path = data.get("json_path", "")
        if json_path and os.path.isfile(json_path):
            with open(json_path, "r", encoding="utf-8") as fh:
                col_a.download_button(
                    "📄 Download JSON",
                    data=fh.read(),
                    file_name=os.path.basename(json_path),
                    mime="application/json",
                    use_container_width=True,
                )

        csv_path = data.get("csv_path", "")
        if csv_path and os.path.isfile(csv_path):
            with open(csv_path, "r", encoding="utf-8") as fh:
                col_b.download_button(
                    "📊 Download CSV",
                    data=fh.read(),
                    file_name=os.path.basename(csv_path),
                    mime="text/csv",
                    use_container_width=True,
                )

        html_path = data.get("html_path", "")
        if html_path and os.path.isfile(html_path):
            with open(html_path, "r", encoding="utf-8") as fh:
                col_c.download_button(
                    "🌐 Download HTML",
                    data=fh.read(),
                    file_name=os.path.basename(html_path),
                    mime="text/html",
                    use_container_width=True,
                )

else:
    st.info("👈 Configure your scan in the sidebar and press **Start Scan** to begin.")
    st.markdown("---")

    # Feature overview
    col_left, col_right = st.columns(2)
    with col_left:
        st.markdown(
            """
            ### ✨ Features
            - 🔍 **Host Discovery** — ARP/Ping sweep on any subnet
            - 🔓 **Port Scanning** — Service version detection via Nmap
            - 🛡️ **Risk Analysis** — Automated HIGH/MEDIUM/LOW classification
            - 🗺️ **Topology Graph** — Visual network map
            - 📊 **Interactive Charts** — Port & risk distribution
            - 📁 **Multi-format Reports** — JSON, CSV, HTML, PDF
            """
        )
    with col_right:
        st.markdown(
            """
            ### ⚡ Quick Start
            1. Enter the target subnet (auto-detected by default)
            2. Choose a port range
            3. Click **Start Scan**
            4. Explore results in the tabs above
            5. Download reports as needed

            > ⚠️ *Requires Nmap installed on the system and appropriate privileges.*
            """
        )
