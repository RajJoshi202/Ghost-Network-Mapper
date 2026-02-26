# Ghost Network Mapper 🔍👻

> **Map your network. Know your exposure. Secure your perimeter.**

---

## ⚠️ Disclaimer

**Ghost Network Mapper is intended strictly for educational purposes and authorized network testing only.** Never run this tool on networks you do not own or have explicit written permission to scan. Unauthorized network scanning may be illegal in your jurisdiction.

---

## 📋 Overview

Ghost Network Mapper is a Python-based network reconnaissance and visualization tool designed for cybersecurity students and professionals. It automates the process of discovering devices on a local subnet, scanning for open ports and running services via Nmap, evaluating potential security risks, and generating professional reports — all from a single command.

Whether you're auditing your home lab, learning about network security, or preparing for a cybersecurity internship, Ghost Network Mapper provides hands-on experience with the same techniques used by professional penetration testers — wrapped in clean, well-documented Python code that demonstrates real-world engineering practices.

---

## 🎯 Features

- **Automatic Subnet Detection** — Identifies your active network interface and subnet automatically
- **Host Discovery** — ARP/ping sweep to find all live devices on the network
- **Port Scanning** — Configurable port range scanning with service version detection
- **OS Fingerprinting** — Combines Nmap OS detection with TTL-based heuristics
- **Service Banner Grabbing** — Extracts banners from common services (FTP, SSH, HTTP, etc.)
- **Risk Analysis Engine** — Classifies every open port as HIGH, MEDIUM, or LOW risk
- **Vulnerability Hints** — Maps open ports to known CVEs and attack descriptions
- **Actionable Recommendations** — Provides remediation steps for every finding
- **Network Topology Graph** — Visual network map with color-coded risk nodes (NetworkX + Matplotlib)
- **Interactive Charts** — Port distribution and risk pie charts (Plotly)
- **Multi-Format Reports** — Export to JSON, CSV, HTML (dark-themed), and PDF
- **Multithreaded Scanning** — Concurrent host and port scanning via ThreadPoolExecutor
- **Rich CLI Experience** — Progress bars, colored output, and formatted tables (Rich)
- **Streamlit GUI** — Optional web-based dashboard for interactive scanning
- **Production-Grade Logging** — Timestamped log files with console and file output

---

## 🏗️ Architecture

Ghost Network Mapper follows a modular pipeline architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                        main.py (CLI)                            │
│                    gui/streamlit_app.py (GUI)                   │
└──────────┬──────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────┐     ┌──────────────────────┐
│    scanner.py        │────▶│    analyzer.py        │
│  • Host Discovery    │     │  • Risk Classification│
│  • Port Scanning     │     │  • Vuln Hints         │
│  • Banner Grabbing   │     │  • Recommendations    │
│  • OS Fingerprinting │     │  • Summary Stats      │
└─────────────────────┘     └──────────┬───────────┘
                                       │
                            ┌──────────▼───────────┐
                            │   visualizer.py       │
                            │  • Topology Graph     │
                            │  • Port Bar Chart     │
                            │  • Risk Pie Chart     │
                            └──────────┬───────────┘
                                       │
                            ┌──────────▼───────────┐
                            │ report_generator.py   │
                            │  • JSON Export        │
                            │  • CSV Export         │
                            │  • HTML Report        │
                            │  • PDF Report         │
                            └──────────────────────┘
                                       │
                            ┌──────────▼───────────┐
                            │      utils.py         │
                            │  • Logging Setup      │
                            │  • Subnet Detection   │
                            │  • MAC Vendor Lookup   │
                            │  • Risky Ports DB      │
                            └──────────────────────┘
```

---

## 🛠️ Tech Stack

| Library | Purpose | Why Chosen |
|---------|---------|------------|
| `python-nmap` | Nmap Python bindings | Industry-standard network scanner integration |
| `networkx` | Graph data structures | Flexible network topology modeling |
| `matplotlib` | Static graph rendering | Publication-quality topology PNG output |
| `plotly` | Interactive charts | Rich, dark-themed, client-side interactive charts |
| `pandas` | Data manipulation | Efficient tabular data handling for CSV export |
| `rich` | CLI formatting | Beautiful progress bars, tables, panels, and colored output |
| `streamlit` | Web dashboard | Rapid prototyping of interactive data apps |
| `netifaces` | Network interfaces | Cross-platform network interface enumeration |
| `requests` | HTTP client | MAC vendor API lookups |
| `weasyprint` | HTML → PDF | High-fidelity PDF report generation |
| `Pillow` | Image processing | Image handling support for reports |
| `numpy` | Numerical computing | Array operations for data processing |

---

## 📦 Installation

### Prerequisites

- **Python 3.9+**
- **Nmap** installed on your system:
  - **Linux:** `sudo apt install nmap`
  - **macOS:** `brew install nmap`
  - **Windows:** Download from [nmap.org](https://nmap.org/download.html), add to PATH

### Setup

```bash
git clone https://github.com/yourusername/ghost-network-mapper
cd ghost-network-mapper
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## 🚀 Usage

### CLI

```bash
# Auto-detect subnet, scan common ports (1-1024)
sudo python main.py

# Specify subnet and full port range
sudo python main.py --subnet 192.168.1.0/24 --ports full

# Verbose output, custom output directory
sudo python main.py --subnet 10.0.0.0/24 --output ./my_scan --verbose

# Skip PDF generation
sudo python main.py --no-pdf

# Windows (run as Administrator)
python main.py --subnet 192.168.1.0/24
```

### CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--subnet` | Auto-detect | Target subnet in CIDR notation |
| `--ports` | `1-1024` | Port range (`"1-1024"` or `"full"` for 1-65535) |
| `--output` | `./outputs` | Output directory for reports and graphs |
| `--timeout` | `120` | Scan timeout in seconds |
| `--gui` | — | Launch Streamlit GUI instead |
| `--no-pdf` | — | Skip PDF generation |
| `--verbose` | — | Enable debug-level logging |

### GUI (Streamlit)

```bash
streamlit run gui/streamlit_app.py
```

---

## 📊 Output Files

| File | Location | Description |
|------|----------|-------------|
| `scan_TIMESTAMP.json` | `outputs/reports/` | Complete scan data in JSON format |
| `scan_TIMESTAMP.csv` | `outputs/reports/` | Flattened host+port data for spreadsheets |
| `scan_TIMESTAMP.html` | `outputs/reports/` | Self-contained dark-themed HTML report |
| `scan_TIMESTAMP.pdf` | `outputs/reports/` | PDF version of the HTML report |
| `topology_TIMESTAMP.png` | `outputs/graphs/` | Network topology graph image |
| `ports_TIMESTAMP.html` | `outputs/graphs/` | Interactive port distribution chart |
| `risk_pie_TIMESTAMP.html` | `outputs/graphs/` | Interactive risk distribution donut chart |
| `scan_TIMESTAMP.log` | `outputs/logs/` | Timestamped scan activity log |

---

## 🖼️ Screenshots

![CLI Output](assets/screenshots/cli_output.png)
![Network Topology](assets/screenshots/topology.png)
![HTML Report](assets/screenshots/html_report.png)
![Streamlit Dashboard](assets/screenshots/streamlit_dashboard.png)

---

## 🔒 Risk Analysis Methodology

Ghost Network Mapper classifies open ports into three risk tiers:

### 🔴 HIGH Risk
Ports that are frequently exploited, commonly targeted by automated attacks, or associated with critical CVEs:
- **21** (FTP) — Plaintext credentials
- **23** (Telnet) — Unencrypted remote access
- **445** (SMB) — EternalBlue / ransomware vector
- **3389** (RDP) — BlueKeep / brute-force
- **5900** (VNC) — Weak authentication
- **6379** (Redis) — Often unauthenticated
- **27017** (MongoDB) — Default no-auth
- **1433** (MSSQL), **3306** (MySQL) — Database exposure

### 🟡 MEDIUM Risk
Ports running services that need careful configuration:
- **22** (SSH), **25** (SMTP), **53** (DNS), **80** (HTTP), **110** (POP3), **139** (NetBIOS), **143** (IMAP), **8080/8443** (Alt HTTP/S), **5432** (PostgreSQL), **1521** (Oracle)

### 🟢 LOW Risk
All other open ports — the service is exposed but not in the known-risky list.

### NONE
Host has no open ports detected in the scanned range.

Each host receives the **highest** risk level found across all its open ports. Vulnerability hints provide specific CVE references and attack descriptions to help prioritize remediation.

---

## 💼 Skills Demonstrated (for CV/Portfolio)

- Network reconnaissance and host discovery
- Service enumeration with Nmap integration
- Concurrent programming with Python threading
- Data analysis and transformation with Pandas
- Graph theory and network visualization (NetworkX)
- Interactive data visualization (Plotly)
- CLI design with Rich library
- Web dashboard development with Streamlit
- Report generation (HTML, PDF, JSON, CSV)
- Security risk assessment methodology
- Python OOP and modular architecture
- Error handling and production-grade logging

---

## 🔮 Future Improvements

- CVE database integration (NVD API) for real-time vulnerability matching
- Passive OS fingerprinting via packet sniffing (Scapy)
- Scheduled scans with change detection alerts
- Network traffic anomaly detection
- Integration with Shodan API for internet-facing host enrichment
- Docker containerization for portable deployment
- Export to SIEM-compatible format (JSON-CEF)
- Database-backed scan history with diff reports

---

## 📄 License

MIT License — see [LICENSE](LICENSE) file.

---

## 👤 Author

**[Joshi Raj]** | Cybersecurity Student

- 🔗 [LinkedIn](https://www.linkedin.com/in/raj-joshi-95072735a/)
- 🐙 [GitHub](https://github.com/RajJoshi202)

---

*Built with ❤️ for the cybersecurity community.*
