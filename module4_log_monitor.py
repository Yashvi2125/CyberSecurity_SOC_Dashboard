import sqlite3
from collections import defaultdict
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import psutil  

# ==============================
# CONFIGURATION
# ==============================

DB_FILE = "logs.db"

TRAFFIC_THRESHOLD = 20
PORT_SCAN_THRESHOLD = 8
CPU_THRESHOLD = 80  

EMAIL_ALERTS = True  

EMAIL_SENDER = "purohityashvi2125@gmail.com"
EMAIL_PASSWORD = "zdaj lqfu stnj sulu"
EMAIL_RECEIVER = "purohityashvi2125@gmail.com"


# ==============================
# EMAIL FUNCTION
# ==============================

def send_email_alert(subject, message):
    if not EMAIL_ALERTS:
        return

    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        server.quit()

        print("📧 Email alert sent!")

    except Exception as e:
        print("❌ Email failed:", e)


# ==============================
# READ LOGS FROM DATABASE
# ==============================

def fetch_logs():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("SELECT timestamp, src_ip, dst_ip, protocol, port FROM packet_logs")
    logs = cur.fetchall()

    conn.close()
    return logs


# ==============================
# ANALYZE NETWORK LOGS
# ==============================

def analyze_logs(logs):
    traffic_count = defaultdict(int)
    port_scan = defaultdict(set)

    alerts = []

    for log in logs:
        timestamp, src_ip, dst_ip, protocol, port = log

        traffic_count[src_ip] += 1
        port_scan[src_ip].add(port)

    for ip in traffic_count:
        if traffic_count[ip] > TRAFFIC_THRESHOLD:
            msg = f"[HIGH] Suspicious Traffic from {ip} ({traffic_count[ip]} requests)"
            alerts.append(msg)

    for ip in port_scan:
        if len(port_scan[ip]) > PORT_SCAN_THRESHOLD:
            msg = f"[MEDIUM] Port Scanning detected from {ip} ({len(port_scan[ip])} ports)"
            alerts.append(msg)

    return alerts


# ==============================
# SYSTEM ACTIVITY MONITOR
# ==============================

def check_system_activity():
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent

    alerts = []

    if cpu > CPU_THRESHOLD:
        alerts.append(f"[HIGH] High CPU Usage detected: {cpu}%")

    if memory > CPU_THRESHOLD:
        alerts.append(f"[MEDIUM] High Memory Usage detected: {memory}%")

    return alerts


# ==============================
# MAIN FUNCTION
# ==============================

def main():
    print("\n🛡 Log Monitoring System Started...\n")

    logs = fetch_logs()

    print(f"📊 Total Logs Analyzed: {len(logs)}\n")

    network_alerts = analyze_logs(logs)
    system_alerts = check_system_activity()

    all_alerts = network_alerts + system_alerts

    if all_alerts:
        print("🚨 ALERTS DETECTED:\n")

        for alert in all_alerts:
            print("🚨", alert)

            # send email
            send_email_alert("Security Alert", alert)

    else:
        print("✅ No anomalies detected")

    print("\n📁 Alerts ready for dashboard integration")


# ==============================
# RUN
# ==============================

if __name__ == "__main__":
    main()