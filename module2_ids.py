# =============================================================
#   MODULE 2 — Intrusion Detection System 
# =============================================================

from collections import defaultdict
from datetime import datetime
import sqlite3, time, threading, sys

DB_FILE = "logs.db"

# ─────────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur  = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ids_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            rule_name TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            details TEXT,
            severity TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_alert(rule_name, src_ip, dst_ip, protocol, details, severity):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        INSERT INTO ids_alerts (timestamp, rule_name, src_ip, dst_ip, protocol, details, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        rule_name, src_ip, dst_ip, protocol, details, severity
    ))
    conn.commit()
    conn.close()

    print(f"🚨 [{severity}] {rule_name} from {src_ip}")


# ─────────────────────────────────────────────
#  RULE ENGINE
# ─────────────────────────────────────────────

connection_counter = defaultdict(int)
alerted = set()

def check_rules(src_ip, dst_ip, protocol, port):
    key = src_ip
    connection_counter[key] += 1

    # RULE 1: ICMP (Unauthorized)
    if protocol == "ICMP":
        alert_key = (src_ip, "ICMP")
        if alert_key not in alerted:
            save_alert("ICMP Activity", src_ip, dst_ip, protocol,
                       "Suspicious ICMP traffic", "MEDIUM")
            alerted.add(alert_key)

    # RULE 2: Brute Force
    if connection_counter[key] > 5:
        alert_key = (src_ip, "BRUTE")
        if alert_key not in alerted:
            save_alert("Brute Force Attempt", src_ip, dst_ip, protocol,
                       "Multiple repeated attempts", "HIGH")
            alerted.add(alert_key)

    # RULE 3: DoS
    if connection_counter[key] > 10:
        alert_key = (src_ip, "DOS")
        if alert_key not in alerted:
            save_alert("DoS Attack", src_ip, dst_ip, protocol,
                       "High traffic detected", "CRITICAL")
            alerted.add(alert_key)


# ─────────────────────────────────────────────
#  READ FROM MODULE 1 (DATABASE MODE)
# ─────────────────────────────────────────────

def run_from_logs():
    print("\n  [DB] Reading logs from Module 1...\n")

    while True:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT src_ip, dst_ip, protocol, port 
            FROM packet_logs 
            ORDER BY id DESC LIMIT 50
        """)

        logs = cursor.fetchall()
        print("Logs fetched:", len(logs))
        conn.close()

        for log in logs:
            src_ip, dst_ip, protocol, port = log

            print(f"  [{datetime.now().strftime('%H:%M:%S')}] {protocol} {src_ip} → {dst_ip} Port:{port}")
            check_rules(src_ip, dst_ip, protocol, port)

        time.sleep(3)


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("   🛡️  Intrusion Detection System — Mini SOC Platform")
    print("=" * 60)

    init_db()

    print("\n  Mode : DATABASE (integrated with Module 1)")
    print(f"  DB   : {DB_FILE}\n")

    try:
        run_from_logs()
    except KeyboardInterrupt:
        print("\n\n  [✓] IDS stopped. Alerts saved to logs.db")
        print("=" * 60)