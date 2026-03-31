# 🛡 Cyber Security SOC Dashboard

## 📌 Project Overview
This project is a complete Security Operations Center (SOC) simulation system that monitors network traffic, detects threats, scans vulnerabilities, and secures file transfers.

---

## 🚀 Features

### 1️⃣ Network Monitoring
- Captures live network packets
- Stores logs in SQLite database

### 2️⃣ Intrusion Detection System (IDS)
- Detects:
  - High traffic attacks
  - Port scanning
- Generates alerts

### 3️⃣ Web Vulnerability Scanner
- Detects:
  - SQL Injection
  - Cross-Site Scripting (XSS)

### 4️⃣ Secure File Transfer
- Encrypts files using Fernet encryption
- Decrypts files using key

### 5️⃣ SOC Dashboard
- Real-time monitoring
- Threat alerts
- Network visualization
- Integrated tools

## 🛠 Tech Stack
- Python
- Streamlit
- SQLite
- Pandas
- Cryptography

## ▶️ How to Run
```bash
pip install streamlit pandas requests cryptography
streamlit run module6_dashboard.py
