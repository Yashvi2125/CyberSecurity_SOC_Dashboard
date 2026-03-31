# =============================================================
#   MODULE 1 — Network Traffic Monitor 
#   Mini SOC Platform | Cyber Security Project
# =============================================================

from collections import defaultdict
from datetime import datetime
import sqlite3
import threading
import time
import random
import sys

# ─────────────────────────────────────────────
#  DATABASE SETUP  (single shared logs.db)
# ─────────────────────────────────────────────

DB_FILE = "logs.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur  = conn.cursor()

    # ── packet_logs: every captured/simulated packet ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS packet_logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip    TEXT,
            dst_ip    TEXT,
            protocol  TEXT,
            port      INTEGER
        )
    """)

    # ── alerts: suspicious activity found by Module 1 ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT,
            alert_type TEXT,
            src_ip     TEXT,
            details    TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("  [✓] Database initialised → logs.db")


def log_packet(timestamp, src_ip, dst_ip, protocol, port):
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "INSERT INTO packet_logs (timestamp,src_ip,dst_ip,protocol,port) VALUES (?,?,?,?,?)",
        (timestamp, src_ip, dst_ip, protocol, port)
    )
    conn.commit()
    conn.close()


def log_alert(alert_type, src_ip, details):
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "INSERT INTO alerts (timestamp,alert_type,src_ip,details) VALUES (?,?,?,?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), alert_type, src_ip, details)
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
#  DETECTION THRESHOLDS
# ─────────────────────────────────────────────

PORT_SCAN_THRESHOLD = 15   # unique ports from 1 IP  → port scan
TRAFFIC_SPIKE_LIMIT = 100  # total packets from 1 IP → spike

port_scan_tracker    = defaultdict(set)
traffic_spike_tracker = defaultdict(int)


def detect_port_scan(src_ip, dst_port):
    port_scan_tracker[src_ip].add(dst_port)
    if len(port_scan_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
        msg = f"Touched {len(port_scan_tracker[src_ip])} different ports"
        print(f"\n  🚨 ALERT — Port Scan | {src_ip} | {msg}\n")
        log_alert("Port Scan", src_ip, msg)
        port_scan_tracker[src_ip].clear()


def detect_traffic_spike(src_ip):
    traffic_spike_tracker[src_ip] += 1
    if traffic_spike_tracker[src_ip] >= TRAFFIC_SPIKE_LIMIT:
        msg = f"Sent {traffic_spike_tracker[src_ip]} packets in window"
        print(f"\n  🚨 ALERT — Traffic Spike | {src_ip} | {msg}\n")
        log_alert("Traffic Spike", src_ip, msg)
        traffic_spike_tracker[src_ip] = 0


def handle_packet(src_ip, dst_ip, protocol, dst_port):
    """Core logic — shared by both live and simulation modes."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    port_str  = str(dst_port) if dst_port else "N/A"

    print(f"  [{timestamp}]  {protocol:<5}  {src_ip:<20} → {dst_ip:<20}  Port: {port_str}")

    if protocol == "TCP" and dst_port:
        detect_port_scan(src_ip, dst_port)
    detect_traffic_spike(src_ip)
    log_packet(timestamp, src_ip, dst_ip, protocol, dst_port)


def reset_trackers():
    while True:
        time.sleep(60)
        port_scan_tracker.clear()
        traffic_spike_tracker.clear()
        print("\n  [*] Trackers reset (60-sec window)\n")


# ─────────────────────────────────────────────
#  SIMULATION MODE  (no sudo, no real traffic)
# ─────────────────────────────────────────────

FAKE_IPS    = ["192.168.1.10","192.168.1.20","10.0.0.5","172.16.0.3","203.0.113.99"]
FAKE_DST    = ["192.168.1.1","8.8.8.8","10.0.0.1"]
PROTOCOLS   = ["TCP","UDP","ICMP"]
COMMON_PORTS= [22,80,443,8080,21,53,3306,3389,445,23]

def run_simulation():
    print("  [SIM] Simulation mode active — generating fake traffic\n")
    # Occasionally simulate a port scanner (one IP hits many ports)
    scanner_ip = "192.168.1.99"
    scan_round = 0

    while True:
        scan_round += 1

        # Every 5 rounds inject a port-scan burst from scanner_ip
        if scan_round % 5 == 0:
            for p in random.sample(range(1024, 9999), 20):
                handle_packet(scanner_ip, "192.168.1.1", "TCP", p)
                time.sleep(0.05)
        else:
            src  = random.choice(FAKE_IPS)
            dst  = random.choice(FAKE_DST)
            proto= random.choice(PROTOCOLS)
            port = random.choice(COMMON_PORTS) if proto != "ICMP" else None
            handle_packet(src, dst, proto, port)

        time.sleep(0.3)  


# ─────────────────────────────────────────────
#  LIVE MODE  (requires scapy + sudo)
# ─────────────────────────────────────────────

def run_live():
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP

        def process_packet(packet):
            if not packet.haslayer(IP):
                return
            src_ip   = packet[IP].src
            dst_ip   = packet[IP].dst
            dst_port = None
            protocol = "OTHER"

            if packet.haslayer(TCP):
                protocol, dst_port = "TCP", packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol, dst_port = "UDP", packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            if protocol != "OTHER":
                handle_packet(src_ip, dst_ip, protocol, dst_port)

        print("  [LIVE] Capturing real packets. Press Ctrl+C to stop.\n")
        sniff(prn=process_packet, store=False, count=0)

    except ImportError:
        print("  [!] Scapy not installed. Falling back to simulation mode.")
        run_simulation()
    except PermissionError:
        print("  [!] Permission denied. Run with sudo for live mode.")
        print("  [!] Falling back to simulation mode.\n")
        run_simulation()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("   🛡️  Network Traffic Monitor — Mini SOC Platform")
    print("=" * 60)

    init_db()

    threading.Thread(target=reset_trackers, daemon=True).start()

    # Pass  --live  flag to use real traffic
    mode = "live" if "--live" in sys.argv else "sim"

    print(f"\n  Mode : {'LIVE (real traffic)' if mode=='live' else 'SIMULATION (demo)'}")
    print(f"  DB   : {DB_FILE}")
    print(f"\n  {'Timestamp':<22} {'Proto':<6} {'Source IP':<22} {'Dest IP':<22} Port")
    print("  " + "-" * 78)

    try:
        if mode == "live":
            run_live()
        else:
            run_simulation()
    except KeyboardInterrupt:
        print("\n\n  [✓] Monitor stopped. Logs saved to logs.db")
        print("=" * 60)