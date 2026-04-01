import subprocess
import sys
import time
import webbrowser

print("🚀 Starting Cyber Security SOC System...\n")

# ==============================
# START MODULE 1 (Network Monitor)
# ==============================
print("📡 Starting Network Monitor...")
subprocess.Popen([sys.executable, "module1_network_monitor.py"])

time.sleep(2)

# ==============================
# START MODULE 4 (Log Monitor + Email Alerts)
# ==============================
print("🚨 Starting Log Monitor (Alerts + Email)...")
subprocess.Popen([sys.executable, "module4_log_monitor.py"])

time.sleep(2)

# ==============================
# START DASHBOARD (Module 6)
# ==============================
print("🖥️ Launching Dashboard...")
subprocess.Popen([sys.executable, "-m", "streamlit", "run", "module6_dashboard.py"])

time.sleep(5)

# ==============================
# OPEN DASHBOARD IN BROWSER
# ==============================
webbrowser.open("http://localhost:8501")

print("\n✅ All modules started successfully!")
print("👉 Dashboard opened in browser")
print("👉 Press CTRL+C to stop everything")
