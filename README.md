# MiniSOC
# 🛡 Overview

MINI SOC (Security Operations Center) is a Python-based defensive cybersecurity platform designed for educational, research, and blue team monitoring purposes.
It simulates the core functionalities of a lightweight SOC environment by combining:

Threat detection
Event correlation
Network monitoring
SSH brute-force detection
Packet inspection
Real-time dashboarding
Alert management
System metrics collection
Report generation

This project was developed as a Final Year Cybersecurity Project and demonstrates how modern SOC architectures operate internally.

# 🎯 Project Goals

The main goal of MINI SOC is to provide a simplified but practical implementation of:

SIEM-style event processing
Threat scoring
Real-time monitoring
Security alerting
Blue team defensive operations
Network visibility
Log analysis
Attack simulation

The project is intentionally verbose and modular for:

academic evaluation
demonstrations
cybersecurity learning
SOC architecture understanding
# 🧠 Core Features
✅ Unified Threat Engine

Centralized threat analysis engine responsible for:

maintaining per-IP risk scores
correlating suspicious activities
escalating threat severity
tracking malicious behavior history
✅ SSH Brute Force Detection

Monitors:

/var/log/auth.log

Detects:

failed SSH logins
repeated authentication attempts
brute-force behavior
✅ Packet Sniffing & Port Scan Detection

Uses Scapy to:

capture TCP packets
monitor suspicious ports
detect recon activity
identify repeated port access patterns

Monitored ports include:

21 (FTP)
22 (SSH)
23 (Telnet)
25 (SMTP)
80 (HTTP)
443 (HTTPS)
3306 (MySQL)
3389 (RDP)
✅ Real-Time Threat Scoring

Every suspicious event increases an IP’s risk score.

Threat levels:

LOW
MEDIUM
HIGH
CRITICAL

This simulates real SOC/SIEM correlation logic.

✅ Event Correlation

The system correlates:

SSH attacks
port scans
high-frequency suspicious events

and automatically escalates threats.

✅ SQLite Persistence

All alerts, events, and metrics are stored inside:

soc.db

Stored data includes:

alerts
raw events
CPU usage
memory usage
uptime
packet counts
✅ Flask Web Dashboard

Built-in web interface displaying:

active alerts
threat statistics
CPU/memory metrics
SOC uptime
detected IP addresses
packet statistics

Dashboard auto-refreshes every 5 seconds.

✅ Network Scanner

Uses Nmap to:

discover reachable hosts
identify open services
monitor network visibility
✅ Report Generation

Automatically generates:

TXT reports
JSON reports

Useful for:

audits
demonstrations
forensic review
academic evaluation
✅ Attack Simulation Mode

Includes a built-in attack simulator capable of generating:

fake SSH brute-force attacks
simulated port scans

This helps demonstrate the SOC functionality in controlled environments.

# 🏗 Architecture

The project contains multiple internal modules:

Component	Purpose
Threat Engine	Risk analysis & event correlation
Packet Analyzer	TCP packet inspection
SSH Monitor	SSH authentication log monitoring
Metrics Collector	CPU/RAM/system monitoring
Network Scanner	Host discovery using Nmap
Dashboard	Flask-based monitoring UI
Database Manager	SQLite storage layer
Report Generator	TXT & JSON reporting
Attack Simulator	Demo attack generation
⚙ Technologies Used
Programming Language
Python 3
Libraries
psutil
scapy
flask
sqlite3
python-nmap
threading
logging
📦 Installation
Clone Repository
git clone <repository-url>
cd MINI_SOC
Install Dependencies
pip install flask psutil scapy python-nmap
Install Nmap
Ubuntu/Debian
sudo apt install nmap
Windows

Install from:
https://nmap.org/download.html

# 🚀 Running MINI SOC
Linux

Run with root privileges for packet sniffing:

sudo python3 MINI_SOC.py
# 🌐 Access Dashboard

Open browser:

http://localhost:8081

or

http://<your-ip>:8081
# 📂 Project Structure
MINI_SOC/
│
├── MINI_SOC.py
├── soc.db
├── logs/
│   └── soc.log
│
├── reports/
│   ├── soc_report.txt
│   └── soc_report.json
│
└── README.md
# 📊 Dashboard Features

The dashboard provides:

real-time alerts
system health metrics
active threat monitoring
severity visualization
packet statistics
uptime tracking
# 🔥 Threat Detection Logic

The system currently detects:

SSH brute-force attempts
port scanning activity
repeated suspicious events
high-frequency attack behavior

Threats are automatically escalated based on risk scores.

# 🧪 Demo Mode

The attack simulator continuously generates:

simulated port scans
simulated SSH failures

Useful for:

classroom demos
presentations
project viva
SOC demonstrations
# 📑 Generated Reports

Reports include:

threat summaries
recent alerts
CPU/memory metrics
packet statistics
SOC uptime

Formats:

TXT
JSON
# ⚠ Limitations

This project is intended for:

educational use
demonstrations
research purposes

It is NOT production-ready because:

SQLite has scalability limitations
detection logic is simplified
authentication is minimal
no distributed architecture exists
packet processing is basic
# 🔒 Security Notes

For packet sniffing:

Linux users should run as root
Firewall rules may affect packet capture
SSH monitoring requires access to auth logs
# 🔮 Future Improvements

Possible future enhancements:

ElasticSearch integration
Wazuh/Suricata integration
MITRE ATT&CK mapping
JWT authentication
WebSocket real-time streaming
Machine learning anomaly detection
GeoIP intelligence
Docker deployment
REST API support
Email/Discord alerting
# 🎓 Educational Value

MINI SOC demonstrates concepts used in:

SOC operations
SIEM systems
intrusion detection
blue team workflows
threat intelligence
security monitoring

It is suitable for:

cybersecurity students
blue team learners
SOC beginners
academic research
# 👨‍💻 Author

Mahammad Akifovich Gulmammadov



# 📜 License

This project is intended for educational and research purposes only.
