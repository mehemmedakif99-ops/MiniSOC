#!/usr/bin/env python3
"""
============================================================
                MINI SOC – FINAL EDITION
        Defensive Security | Blue Team | Final Year Project

Author  : Prashant Gautam
============================================================

ARCHITECTURE OVERVIEW
---------------------
✔ Unified Threat Engine
✔ Event Correlation
✔ SQLite Persistence
✔ Thread-Safe Operations
✔ Modular Expansion (EDR-ready)

NOTE:
This project is intentionally verbose (1000+ LOC)
for academic, demo, and evaluation purposes.
"""

# ==========================================================
# ========================= IMPORTS ========================
# ==========================================================

import os
import re
import sys
import time
import json
import socket
import sqlite3
import logging
import threading
import platform
import random
from datetime import datetime
from collections import defaultdict, deque

# External libraries
import psutil
import nmap
from flask import Flask, render_template_string

# Scapy (requires root)
try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# ==========================================================
# ===================== GLOBAL CONFIG ======================
# ==========================================================
PROJECT_NAME = "MINI_SOC"
VERSION = "1.0-FINAL"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "soc.db")
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

NETWORK_RANGE = "192.168.1.0/24"
MONITORED_PORTS = [21, 22, 23, 25, 80, 443, 3306, 3389]
ALERT_THRESHOLD = 5

WEB_HOST = "0.0.0.0"
WEB_PORT = 8081   

METRIC_INTERVAL = 10
SSH_FAIL_WEIGHT = 15
PORT_SCAN_WEIGHT = 5


# ==========================================================
# ===================== DIRECTORY SETUP ====================
# ==========================================================

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


# ==========================================================
# ===================== LOGGING SETUP ======================
# ==========================================================

LOG_FILE = os.path.join(LOG_DIR, "soc.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logging.info("Starting MINI SOC Platform")
logging.info(f"OS        : {platform.system()} {platform.release()}")
logging.info(f"Python    : {platform.python_version()}")
logging.info(f"Version   : {VERSION}")


# ==========================================================
# ===================== GLOBAL LOCKS =======================
# ==========================================================

db_lock = threading.Lock()
state_lock = threading.Lock()


# ==========================================================
# ===================== SOC RUNTIME STATE ==================
# ==========================================================

soc_state = {
    "start_time": time.time(),
    "total_packets": 0,
    "events_processed": 0
}

# ==========================================================
# ===================== DATABASE ENGINE ===================
# ==========================================================

class DatabaseManager:
    """
    Handles all SQLite operations.
    Thread-safe by design.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self._initialize()

    def _initialize(self):
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()

            # Alerts table
            cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT,
                category TEXT,
                severity INTEGER,
                message TEXT,
                source_ip TEXT
            )
            """)

            # Metrics table
            cur.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT,
                cpu REAL,
                memory REAL,
                packets INTEGER,
                uptime INTEGER
            )
            """)

            # Events table (raw telemetry)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT,
                ip TEXT,
                event_type TEXT,
                weight INTEGER
            )
            """)

            conn.commit()
            conn.close()

        logging.info("Database initialized successfully")

    # ---------------- ALERTS ----------------

    def save_alert(self, category, severity, message, ip):
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO alerts VALUES (NULL, datetime('now'), ?, ?, ?, ?)",
                (category, severity, message, ip)
            )
            conn.commit()
            conn.close()

    def fetch_alerts(self, limit=50):
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            rows = cur.execute(
                "SELECT time, category, severity, message, source_ip "
                "FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
            conn.close()
            return rows

    # ---------------- METRICS ----------------

    def save_metric(self, cpu, memory, packets, uptime):
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO metrics VALUES (NULL, datetime('now'), ?, ?, ?, ?)",
                (cpu, memory, packets, uptime)
            )
            conn.commit()
            conn.close()

    def fetch_latest_metric(self):
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            row = cur.execute(
                "SELECT cpu, memory, packets, uptime "
                "FROM metrics ORDER BY id DESC LIMIT 1"
            ).fetchone()
            conn.close()
            return row

    # ---------------- EVENTS ----------------

    def save_event(self, ip, event_type, weight):
        with db_lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO events VALUES (NULL, datetime('now'), ?, ?, ?)",
                (ip, event_type, weight)
            )
            conn.commit()
            conn.close()


# ==========================================================
# ===================== DATABASE INSTANCE ==================
# ==========================================================

db = DatabaseManager(DB_FILE)

# ==========================================================
# ===================== GEO-IP (BASIC) =====================
# ==========================================================

def geoip_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


# ==========================================================
# ===================== THREAT ENGINE ======================
# ==========================================================

class ThreatEngine:
    """
    CENTRAL SOC BRAIN

    Responsibilities:
    -----------------
    ✔ Maintain per-IP risk score
    ✔ Track last seen activity
    ✔ Correlate multiple attack patterns
    ✔ Escalate severity automatically
    ✔ Feed alerts to database
    """

    def __init__(self, db_manager):
        self.db = db_manager
        self.risk_scores = defaultdict(int)
        self.last_seen = {}
        self.threat_level = {}
        self.event_history = defaultdict(lambda: deque(maxlen=50))
        self.lock = threading.Lock()

    # ---------------- INTERNAL UTILS ----------------

    def _calculate_level(self, score):
        if score < 20:
            return "LOW"
        elif score < 50:
            return "MEDIUM"
        elif score < 80:
            return "HIGH"
        else:
            return "CRITICAL"

    def _escalate(self, ip, reason):
        level = self.threat_level.get(ip, "UNKNOWN")
        score = self.risk_scores.get(ip, 0)

        msg = f"THREAT ESCALATION [{level}] {ip} :: {reason}"
        self.db.save_alert("THREAT_ESCALATION", score, msg, ip)
        logging.critical(msg)

    # ---------------- PUBLIC API ----------------

    def add_event(self, ip, weight, event_type):
        with self.lock:
            self.risk_scores[ip] += weight
            self.last_seen[ip] = time.time()

            self.event_history[ip].append({
                "time": time.time(),
                "type": event_type,
                "weight": weight
            })

            self.db.save_event(ip, event_type, weight)

            level = self._calculate_level(self.risk_scores[ip])
            self.threat_level[ip] = level

            # ---- Correlation Rules ----
            if event_type == "SSH_BRUTEFORCE" and self.risk_scores[ip] >= 60:
                self._escalate(ip, "Multiple SSH failures detected")

            if event_type == "PORT_SCAN" and self.risk_scores[ip] >= 40:
                self._escalate(ip, "Recon + Port scanning behavior")

            if len(self.event_history[ip]) >= 10:
                self._escalate(ip, "High frequency suspicious activity")

            return level

    def cleanup(self, ttl=300):
        """
        Remove inactive IPs from memory
        """
        now = time.time()
        with self.lock:
            for ip in list(self.last_seen.keys()):
                if now - self.last_seen[ip] > ttl:
                    self.last_seen.pop(ip, None)
                    self.risk_scores.pop(ip, None)
                    self.threat_level.pop(ip, None)
                    self.event_history.pop(ip, None)

    def summary(self):
        with self.lock:
            return {
                "total_ips": len(self.risk_scores),
                "critical": sum(1 for v in self.threat_level.values() if v == "CRITICAL"),
                "high": sum(1 for v in self.threat_level.values() if v == "HIGH"),
                "medium": sum(1 for v in self.threat_level.values() if v == "MEDIUM"),
                "low": sum(1 for v in self.threat_level.values() if v == "LOW")
            }

    def get_score(self, ip):
        """Thread-safe read that never mutates the underlying defaultdict."""
        with self.lock:
            return self.risk_scores.get(ip, 0)


# ==========================================================
# ===================== THREAT ENGINE INSTANCE =============
# ==========================================================

threat_engine = ThreatEngine(db)

# ==========================================================
# ===================== ATTACK SIMULATOR ===================
# ==========================================================

class AttackSimulator:
    """
    Generates controlled fake attacks
    Used for demo / viva / testing
    """

    def __init__(self, engine):
        self.engine = engine
        self.fake_ips = [
            "10.10.10.5",
            "45.33.12.90",
            "185.220.101.7",
            "172.16.1.100",
            "192.168.56.23"
        ]

    def simulate_port_scan(self):
        ip = random.choice(self.fake_ips)
        logging.warning(f"[SIM] Port scan started from {ip}")
        for _ in range(5):
            self.engine.add_event(ip, PORT_SCAN_WEIGHT, "PORT_SCAN")
            msg = f"[SIMULATED] Port scan from {ip}"
            db.save_alert("SIM_PORTSCAN", self.engine.get_score(ip), msg, ip)
            time.sleep(0.4)

    def simulate_ssh_bruteforce(self):
        ip = random.choice(self.fake_ips)
        logging.warning(f"[SIM] SSH brute force from {ip}")
        for _ in range(6):
            level = self.engine.add_event(ip, SSH_FAIL_WEIGHT, "SSH_BRUTEFORCE")
            msg = f"[SIMULATED] SSH failure from {ip} | Level={level}"
            db.save_alert("SIM_SSH", self.engine.get_score(ip), msg, ip)
            time.sleep(0.6)

    def run_demo(self):
        self.simulate_port_scan()
        self.simulate_ssh_bruteforce()


attack_simulator = AttackSimulator(threat_engine)

# ==========================================================
# ===================== SSH LOG MONITOR ====================
# ==========================================================

class SSHLogMonitor:
    """
    Monitors /var/log/auth.log for SSH failures
    """

    def __init__(self, engine):
        self.engine = engine
        self.log_path = "/var/log/auth.log"

    def monitor(self):
        if not os.path.exists(self.log_path):
            logging.warning("SSH log file not found")
            return

        logging.info("SSH log monitoring started")

        with open(self.log_path, "r", errors="ignore") as f:
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue

                if "Failed password" in line:
                    ip_match = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
                    if not ip_match:
                        continue

                    ip = ip_match[0]
                    level = self.engine.add_event(ip, SSH_FAIL_WEIGHT, "SSH_BRUTEFORCE")

                    if self.engine.get_score(ip) >= ALERT_THRESHOLD * SSH_FAIL_WEIGHT:
                        msg = f"SSH Bruteforce detected from {ip} ({geoip_lookup(ip)})"
                        db.save_alert("SSH_BRUTEFORCE", self.engine.get_score(ip), msg, ip)
                        logging.warning(msg)


ssh_monitor = SSHLogMonitor(threat_engine)

# ==========================================================
# ===================== DEMO MODE THREAD ===================
# ==========================================================

def demo_mode_loop():
    while True:
        try:
            attack_simulator.run_demo()
        except Exception as e:
            logging.error(f"Demo mode error: {e}")
        time.sleep(20)


# ==========================================================
# ===================== PACKET ANALYZER ====================
# ==========================================================

class PacketAnalyzer:
    """
    Captures TCP packets and detects
    suspicious port access behavior
    """

    def __init__(self, engine):
        self.engine = engine
        self.port_hits = defaultdict(int)

    def handle_packet(self, pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport

        with state_lock:
            soc_state["total_packets"] += 1
            soc_state["events_processed"] += 1

        if dst_port in MONITORED_PORTS:
            self.port_hits[src_ip] += 1
            self.engine.add_event(src_ip, PORT_SCAN_WEIGHT, "PORT_SCAN")

            if self.port_hits[src_ip] == ALERT_THRESHOLD:
                msg = f"Port scan detected from {src_ip} ({geoip_lookup(src_ip)})"
                db.save_alert(
                    "PORT_SCAN",
                    self.engine.get_score(src_ip),
                    msg,
                    src_ip
                )
                logging.warning(msg)

    def start(self):
        if not SCAPY_AVAILABLE:
            logging.error("Scapy not available – packet sniffing disabled")
            return

        logging.info("Packet sniffer started")
        try:
            sniff(filter="tcp", prn=self.handle_packet, store=False)
        except PermissionError:
            logging.error("Run SOC as root to enable packet sniffing")
        except Exception as e:
            logging.error(f"Sniffer error: {e}")


packet_analyzer = PacketAnalyzer(threat_engine)

# ==========================================================
# ===================== NETWORK SCANNER ====================
# ==========================================================

class NetworkScanner:
    """
    Periodic Nmap scan for reachable hosts
    """

    def __init__(self, network_range):
        self.network_range = network_range
        try:
            self.nm = nmap.PortScanner()
        except Exception as e:
            self.nm = None
            logging.error(f"Nmap unavailable – network scanning disabled: {e}")

    def scan(self):
        if self.nm is None:
            logging.warning("Network scan skipped (nmap not available)")
            return

        logging.info(f"Starting network scan: {self.network_range}")
        try:
            self.nm.scan(
                hosts=self.network_range,
                arguments="-p 22,80,443 --open"
            )

            for host in self.nm.all_hosts():
                if self.nm[host].state() == "up":
                    logging.info(f"Host reachable: {host}")
        except Exception as e:
            logging.error(f"Nmap scan failed: {e}")


network_scanner = NetworkScanner(NETWORK_RANGE)

# ==========================================================
# ===================== METRICS COLLECTOR ==================
# ==========================================================

class MetricsCollector:
    """
    Collects system + SOC health metrics
    """

    def __init__(self, db_manager):
        self.db = db_manager
        self.start_time = time.time()

    def collect(self):
        try:
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory().percent

            with state_lock:
                packets = soc_state["total_packets"]

            uptime = int(time.time() - self.start_time)

            self.db.save_metric(cpu, memory, packets, uptime)

            logging.info(
                f"Metrics collected | CPU={cpu}% MEM={memory}% "
                f"Packets={packets} Uptime={uptime}s"
            )

        except Exception as e:
            logging.error(f"Metric collection failed: {e}")

    def loop(self):
        while True:
            self.collect()
            time.sleep(METRIC_INTERVAL)


metrics_collector = MetricsCollector(db)

# ==========================================================
# ===================== BACKGROUND THREADS =================
# ==========================================================

def start_packet_sniffer():
    packet_analyzer.start()

def start_metrics_collector():
    metrics_collector.loop()

def start_network_scanner():
    while True:
        network_scanner.scan()
        time.sleep(300)   # every 5 minutes


# ==========================================================
# ===================== WEB DASHBOARD ======================
# ==========================================================

app = Flask(__name__)

# ==========================================================
# ============== CHROME CONTROL ROUTES =====================
# ==========================================================

@app.route("/demo")
def chrome_demo_attack():
    """
    Trigger demo attacks from Chrome browser
    """
    threading.Thread(
        target=attack_simulator.run_demo,
        daemon=True
    ).start()
    return "<h3>✅ Demo Attack Started</h3>"

@app.route("/report")
def chrome_generate_report():
    """
    Generate SOC reports from browser
    """
    report_generator.generate_text_report()
    report_generator.generate_json_report()
    return "<h3>📄 SOC Reports Generated</h3>"

@app.route("/shutdown")
def chrome_shutdown_soc():
    """
    Safely shutdown SOC from browser
    """
    return "<h3>❌ SOC shutdown disabled for safety</h3>"


SOC_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>MINI SOC Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {
            background-color: #020617;
            color: #e5e7eb;
            font-family: monospace;
            margin: 0;
            padding: 0;
        }
        .header {
            padding: 20px;
            background: #020617;
            border-bottom: 3px solid #22c55e;
            text-align: center;
        }
        .header h1 {
            color: #22c55e;
            margin: 0;
        }
        .header h3 {
            color: #94a3b8;
            margin: 5px 0;
        }
        .container {
            padding: 20px;
        }
        .stats {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }
        .box {
            flex: 1;
            background: #020617;
            border: 1px solid #334155;
            padding: 15px;
            text-align: center;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #334155;
            padding: 8px;
        }
        th {
            background: #0f172a;
        }
        .critical { color: #ef4444; }
        .high { color: #f97316; }
        .medium { color: #eab308; }
        .low { color: #22c55e; }
    </style>
</head>
<body>

<div class="header">
    <h1>🛡 MINI SECURITY OPERATIONS CENTER</h1>
    <h3>Real-Time Threat Monitoring Dashboard</h3>
    <p>Final Year Project | Author: Prashant Gautam</p>
</div>

<div class="container">

<div class="stats">
    <div class="box">
        <h3>Total Packets</h3>
        <p>{{ packets }}</p>
    </div>
    <div class="box">
        <h3>Events Processed</h3>
        <p>{{ events }}</p>
    </div>
    <div class="box">
        <h3>Active Threat IPs</h3>
        <p>{{ threats }}</p>
    </div>
</div>

<div class="stats">
    <div class="box low">LOW<br>{{ summary.low }}</div>
    <div class="box medium">MEDIUM<br>{{ summary.medium }}</div>
    <div class="box high">HIGH<br>{{ summary.high }}</div>
    <div class="box critical">CRITICAL<br>{{ summary.critical }}</div>
</div>

<h2>System Metrics</h2>
{% if metrics %}
<ul>
    <li>CPU Usage: {{ metrics[0] }}%</li>
    <li>Memory Usage: {{ metrics[1] }}%</li>
    <li>Packets Captured: {{ metrics[2] }}</li>
    <li>SOC Uptime: {{ metrics[3] }} seconds</li>
</ul>
{% else %}
<p>No metrics collected yet</p>
{% endif %}

<h2>Recent Alerts</h2>
<table>
<tr>
    <th>Time</th>
    <th>Category</th>
    <th>Severity</th>
    <th>Message</th>
    <th>Source IP</th>
</tr>
{% for a in alerts %}
<tr>
    <td>{{ a[0] }}</td>
    <td>{{ a[1] }}</td>
    <td>{{ a[2] }}</td>
    <td>{{ a[3] }}</td>
    <td>{{ a[4] }}</td>
</tr>
{% endfor %}
</table>

</div>
</body>
</html>
"""

@app.route("/")
def dashboard():
    with state_lock:
        packets = soc_state["total_packets"]
        events = soc_state["events_processed"]

    alerts = db.fetch_alerts(25)
    summary = threat_engine.summary()
    metrics = db.fetch_latest_metric()

    return render_template_string(
        SOC_HTML,
        packets=packets,
        events=events,
        threats=summary["total_ips"],
        summary=summary,
        alerts=alerts,
        metrics=metrics
    )

def start_web_dashboard():
    logging.info(f"Web dashboard running on port {WEB_PORT}")
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False)


# ==========================================================
# ===================== DASHBOARD THREAD ===================
# ==========================================================

def start_web_thread():
    start_web_dashboard()

# ==========================================================
# ===================== SOC REPORT GENERATOR ===============
# ==========================================================

class SOCReportGenerator:
    """
    Generates SOC reports for evaluation, audit, and viva
    Supports TXT and JSON formats
    """

    def __init__(self, threat_engine, db_manager):
        self.engine = threat_engine
        self.db = db_manager

    def generate_text_report(self, filename="soc_report.txt"):
        summary = self.engine.summary()
        metrics = self.db.fetch_latest_metric()
        alerts = self.db.fetch_alerts(20)

        filepath = os.path.join(REPORT_DIR, filename)

        with open(filepath, "w") as f:
            f.write("MINI SOC – FINAL REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated At : {datetime.now()}\n\n")

            f.write("THREAT SUMMARY\n")
            f.write("-" * 40 + "\n")
            for k, v in summary.items():
                f.write(f"{k.upper():15}: {v}\n")

            f.write("\nSYSTEM METRICS (LATEST)\n")
            f.write("-" * 40 + "\n")
            if metrics:
                f.write(f"CPU Usage     : {metrics[0]}%\n")
                f.write(f"Memory Usage  : {metrics[1]}%\n")
                f.write(f"Packets Seen  : {metrics[2]}\n")
                f.write(f"SOC Uptime    : {metrics[3]} sec\n")
            else:
                f.write("No metrics collected\n")

            f.write("\nRECENT ALERTS\n")
            f.write("-" * 40 + "\n")
            for a in alerts:
                f.write(f"[{a[0]}] {a[1]} | {a[3]} | IP={a[4]}\n")

        logging.info(f"SOC text report generated: {filepath}")
        return filepath

    def generate_json_report(self, filename="soc_report.json"):
        summary = self.engine.summary()
        metrics = self.db.fetch_latest_metric()
        alerts = self.db.fetch_alerts(50)

        report = {
            "generated_at": str(datetime.now()),
            "summary": summary,
            "metrics": {
                "cpu": metrics[0] if metrics else None,
                "memory": metrics[1] if metrics else None,
                "packets": metrics[2] if metrics else None,
                "uptime": metrics[3] if metrics else None
            },
            "alerts": [
                {
                    "time": a[0],
                    "category": a[1],
                    "severity": a[2],
                    "message": a[3],
                    "ip": a[4]
                } for a in alerts
            ]
        }

        filepath = os.path.join(REPORT_DIR, filename)

        with open(filepath, "w") as f:
            json.dump(report, f, indent=4)

        logging.info(f"SOC JSON report generated: {filepath}")
        return filepath


report_generator = SOCReportGenerator(threat_engine, db)

# ==========================================================
# ===================== ASCII BANNER =======================
# ==========================================================

def print_banner():
    print(r"""
 ███████╗ ██████╗  ██████╗
 ██╔════╝██╔═══██╗██╔═══
 ███████╗██║   ██║██║   
 ╚════██║██║   ██║██║   
 ███████║╚██████╔╝╚██████╔
 ╚══════╝ ╚═════╝  ╚═════╝

        MINI SECURITY OPERATIONS CENTER
        Defensive Security | Blue Team
        Final Year Project
        Author: Prashant Gautam
    """)

# ==========================================================
# ===================== THREAD STARTERS ====================
# ==========================================================

def start_all_threads():
    threads = []

    # Packet Sniffer
    t_sniff = threading.Thread(
        target=start_packet_sniffer,
        daemon=True
    )
    threads.append(t_sniff)

    # Metrics Collector
    t_metrics = threading.Thread(
        target=start_metrics_collector,
        daemon=True
    )
    threads.append(t_metrics)

    # Network Scanner
    t_scan = threading.Thread(
        target=start_network_scanner,
        daemon=True
    )
    threads.append(t_scan)

    # SSH Log Monitor
    t_ssh = threading.Thread(
        target=ssh_monitor.monitor,
        daemon=True
    )
    threads.append(t_ssh)

    # Demo Mode
    t_demo = threading.Thread(
        target=demo_mode_loop,
        daemon=True
    )
    threads.append(t_demo)

    # Web Dashboard
    t_web = threading.Thread(
        target=start_web_thread,
        daemon=True
    )
    threads.append(t_web)

    for t in threads:
        t.start()

    logging.info(f"{len(threads)} SOC background threads started")
    return threads

# ==========================================================
# ===================== MAIN ORCHESTRATOR ==================
# ==========================================================

def main():
    print_banner()
    logging.info("MINI SOC starting up")

    # Initial network scan
    try:
        network_scanner.scan()
    except Exception as e:
        logging.error(f"Initial scan failed: {e}")

    # Start all background services
    start_all_threads()

    logging.info("MINI SOC fully operational")

    try:
        while True:
            threat_engine.cleanup()
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n[!] CTRL+C detected – shutting down SOC")
        logging.warning("SOC shutdown initiated by user")

        # Generate final reports
        try:
            report_generator.generate_text_report()
            report_generator.generate_json_report()
        except Exception as e:
            logging.error(f"Report generation failed: {e}")

        logging.info("SOC stopped cleanly")
        sys.exit(0)

# ==========================================================
# ===================== ENTRY POINT ========================
# ==========================================================

if __name__ == "__main__":
    main()

# ==========================================================
# ===================== END OF MINI SOC ===================
# ==========================================================
