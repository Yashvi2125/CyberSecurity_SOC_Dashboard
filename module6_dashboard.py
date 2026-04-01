import streamlit as st
import sqlite3
import pandas as pd
import time
import requests
import urllib.parse
from cryptography.fernet import Fernet

DB_FILE = "logs.db"

# ==============================
# PAGE CONFIG
# ==============================
st.set_page_config(page_title="SOC Dashboard", layout="wide")

# ==============================
# BEIGE UI
# ==============================

st.markdown("""
<style>
body { background-color: #f5f1e6; }
.stApp { background-color: #f5f1e6; }

h1 { color: #2c2c2c; font-weight: 700; }
h2, h3 { color: #444; }

section[data-testid="stSidebar"] {
    background-color: #ffffff;
    border-right: 1px solid #e0dcd2;
}

[data-testid="stDataFrame"] {
    background-color: #ffffff;
    border-radius: 10px;
    padding: 10px;
}

.block-container { padding: 2rem 3rem; }

/* 🔥 ADD FROM HERE */
input[type="text"] {
    border: 2px solid #d6cfc2 !important;
    border-radius: 8px !important;
    padding: 6px !important;
}

input[type="text"]:focus {
    border: 2px solid #a68b5b !important;
    box-shadow: 0 0 5px rgba(166,139,91,0.4) !important;
}

div[data-baseweb="select"] {
    border: 2px solid #d6cfc2 !important;
    border-radius: 8px !important;
}

div[data-baseweb="select"]:focus-within {
    border: 2px solid #a68b5b !important;
    box-shadow: 0 0 5px rgba(166,139,91,0.4) !important;
}
/* 🔥 ADD TILL HERE */
            
 /* CARD EFFECT */
[data-testid="stMetric"],
[data-testid="stDataFrame"] {
    background-color: #ffffff;
    padding: 12px;
    border-radius: 12px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
}           

</style>
""", unsafe_allow_html=True)

# ==============================
# LOAD DATA FROM DB
# ==============================
def load_logs():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM packet_logs ORDER BY id DESC LIMIT 200", conn)
    conn.close()
    return df

def load_alerts():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM ids_alerts ORDER BY id DESC LIMIT 20", conn)
    conn.close()
    return df

def run_vulnerability_scan(target):
    results = {
        "SQL Injection": "Not Vulnerable",
        "XSS": "Not Vulnerable"
    }

    headers = {"User-Agent": "Mozilla/5.0"}

    # SQL Injection
    sql_payloads = ["' OR '1'='1", "' OR 1=1--"]

    for payload in sql_payloads:
        test_url = target + urllib.parse.quote(payload)
        try:
            response = requests.get(test_url, headers=headers, timeout=3)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                results["SQL Injection"] = "Vulnerable"
                break
        except:
            pass

    # XSS
    xss_payload = "<script>alert(1)</script>"
    test_url = target + urllib.parse.quote(xss_payload)

    try:
        response = requests.get(test_url, headers=headers, timeout=3)
        if xss_payload in response.text:
            results["XSS"] = "Vulnerable"
    except:
        pass

    return results

def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_data, key):
    f = Fernet(key)
    return f.encrypt(file_data)

def decrypt_file(file_data, key):
    f = Fernet(key)
    return f.decrypt(file_data)

# ==============================
# DETECT ALERTS (IDS + LOG)
# ==============================
def detect_alerts(df):
    alerts = []

    # High traffic detection
    ip_counts = df['src_ip'].value_counts()
    for ip, count in ip_counts.items():
        if count > 50:
            alerts.append(f"🔴 HIGH Traffic from {ip} ({count} requests)")

    # Port scanning detection
    port_counts = df.groupby('src_ip')['port'].nunique()
    for ip, count in port_counts.items():
        if count > 10:
            alerts.append(f"🟡 Port Scanning from {ip} ({count} ports)")

    return alerts

# ==============================
# HEADER
# ==============================
st.markdown("## 🛡 Cyber Security Dashboard")
st.caption("Real-Time SOC Monitoring System")
st.success("System Active 🚀")

st.divider()

# ==============================
# LOAD DATA
# ==============================
df = load_logs()

# ==============================
# SIDEBAR FILTERS
# ==============================
st.sidebar.title("🔎 Filters")

search_ip = st.sidebar.text_input("Search by IP")

protocol = st.sidebar.selectbox(
    "Protocol",
    ["All", "TCP", "UDP", "ICMP"]
)

# APPLY FILTERS
if search_ip:
    df = df[df['src_ip'].astype(str).str.contains(search_ip, case=False)]

if protocol != "All":
    df = df[df['protocol'] == protocol]

# ==============================
# METRICS
# ==============================
total_logs = len(df)

if not df.empty:
    unique_ips = df['src_ip'].nunique()
    total_ports = df['port'].nunique()
else:
    unique_ips = 0
    total_ports = 0

col1, col2, col3 = st.columns(3)

col1.metric("📊 Total Logs", total_logs)
col2.metric("🌐 Unique IPs", unique_ips)
col3.metric("🔌 Active Ports", total_ports)

st.divider()
# ==============================
# TOP ATTACKER 🔥
# ==============================
if not df.empty:
    top_ip = df['src_ip'].value_counts().idxmax()
    top_count = df['src_ip'].value_counts().max()

    st.warning(f"🔥 Top Attacker: {top_ip} ({top_count} requests)")

# ==============================
# ALERT PANEL 🔴
# ==============================
st.subheader("🚨 Threat Detection Panel")
st.caption("Monitoring suspicious activities and IDS alerts")

alerts_df = load_alerts()
logic_alerts = detect_alerts(df)

def highlight_severity(row):
    if row['severity'] == 'CRITICAL':
        return ['background-color: #ffcccc'] * len(row)
    elif row['severity'] == 'HIGH':
        return ['background-color: #ffe5b4'] * len(row)
    else:
        return [''] * len(row)

st.dataframe(alerts_df.style.apply(highlight_severity, axis=1), width="stretch")

if not alerts_df.empty:
    st.error("🔴 Real IDS Alerts Detected")
elif logic_alerts:
    for alert in logic_alerts:
        st.warning(alert)
else:
    st.success("No major threats detected ✅")

st.divider()


# ==============================
# LIVE TRAFFIC TABLE
# ==============================
st.subheader("📡 Live Network Traffic")
st.caption("Real-time packet logs from monitored network")

st.dataframe(df, width="stretch")

st.subheader("🌐 Web Vulnerability Scanner")

target_url = st.text_input("Enter target URL (with parameter)", placeholder="http://127.0.0.1:5000/?input=")

if st.button("🔍 Scan Website"):
    if target_url:
        with st.spinner("Scanning..."):
            scan_results = run_vulnerability_scan(target_url)

        st.success("Scan Completed")

        for key, value in scan_results.items():
            if value == "Vulnerable":
                st.error(f"{key}: {value}")
            else:
                st.success(f"{key}: {value}")
    else:
        st.warning("Please enter a valid URL")

st.divider()

# ==============================
# SECURE FILE TRANSFER (FIXED)
# ==============================
st.subheader("🔐 Secure File Transfer")

uploaded_file = st.file_uploader("Upload a file for encryption", key="enc")

if uploaded_file:
    file_data = uploaded_file.read()

    # Generate key ONLY once per upload
    if "enc_key" not in st.session_state:
        st.session_state.enc_key = generate_key()

    key = st.session_state.enc_key

    encrypted_data = encrypt_file(file_data, key)

    st.success("File Encrypted Successfully 🔐")


    st.download_button(
        label="Download Encrypted File",
        data=encrypted_data,
        file_name="encrypted_file.enc",
        mime="application/octet-stream"
    )

    # Show key
    st.info(f"Encryption Key (Save this!): {key.decode()}")

# ==============================
# DECRYPT FILE
# ==============================
st.subheader("🔓 Decrypt File")

decrypt_file_upload = st.file_uploader("Upload encrypted file", key="dec")

user_key = st.text_input("Enter encryption key")

if decrypt_file_upload and user_key:
    encrypted_data = decrypt_file_upload.read()

    try:
        decrypted_data = decrypt_file(encrypted_data, user_key.encode())

        st.success("File Decrypted Successfully ✅")

        st.download_button(
            label="Download Decrypted File",
            data=decrypted_data,
            file_name="decrypted_file",
            mime="application/octet-stream"
        )

    except Exception:
        st.error("❌ Invalid key or file")

st.divider()        

st.subheader("📊 Network Traffic Overview")

if not df.empty:
    chart_data = df['protocol'].value_counts()
    st.bar_chart(chart_data)

st.divider()

        
# ==============================
# FOOTER
# ==============================
st.caption("Developed for Cyber Security Project • SOC Simulation")

