import csv
from datetime import datetime

from tools.detections.brute_force import detect as bf_detect
from tools.detections.malware import detect as mw_detect
from tools.detections.exfiltration import detect as ex_detect
from tools.correlation.risk_engine import calculate_risk


# ============================
# Load Firewall CSV
# ============================
csv_file = "firewall.csv"

brute_logs = []
exfil_logs = []

with open(csv_file, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)

    for row in reader:
        action = row["action"]
        rule = row["rule_description"].lower()
        protocol = row["protocol"].lower()
        port = row["port_number"]

        timestamp = row["event_time"].replace(" UTC", "").replace(" ", "T")
        src_ip = row["source_ip"]
        host = row["internal_ip"]

        # ===============================
        # BRUTE FORCE (SSH, RDP, FTP)
        # ===============================
        if (
            "ssh" in protocol
            or "rdp" in protocol
            or "ftp" in protocol
            or "remote desktop" in rule
        ):
            if action in ["Deny", "Warning", "Log"]:
                brute_logs.append({
                    "timestamp": timestamp,
                    "source_ip": src_ip,
                    "user": "unknown",
                    "event_type": "login_failed"
                })

        # ===============================
        # DATA EXFILTRATION
        # ===============================
        if action == "Allow" and port in ["21", "22", "443", "3389", "995", "993"]:
            exfil_logs.append({
                "timestamp": timestamp,
                "user": host,
                "destination_ip": src_ip,
                "bytes_sent": 150000000   # simulate large transfer
            })


# ===============================
# Malware (static IOC demo)
# ===============================
malware_logs = [
    {
        "timestamp": "2026-01-12T11:00:00",
        "host": "PC-1",
        "process": "mimikatz.exe",
        "path": "C:\\temp\\mimikatz.exe"
    }
]


# ===============================
# Run Detection Engines
# ===============================
bf_findings = bf_detect(brute_logs)["findings"]
mw_findings = mw_detect(malware_logs)["findings"]
ex_findings = ex_detect(exfil_logs)["findings"]

# ===============================
# Risk Correlation
# ===============================
risk_results = calculate_risk(bf_findings, mw_findings, ex_findings)

# ===============================
# OUTPUT
# ===============================
print("\n===== SIEM DETECTION ENGINE =====\n")

print("Brute Force:")
for f in bf_findings:
    print(f)

print("\nMalware:")
for f in mw_findings:
    print(f)

print("\nExfiltration:")
for f in ex_findings:
    print(f)

print("\nRisk Score:")
for r in risk_results:
    print(r)
