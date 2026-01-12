def calculate_risk(brute_force_findings, malware_findings, exfiltration_findings):
    risk_table = {}

    # Brute Force points
    for f in brute_force_findings:
        host = f.get("source_ip")
        risk_table.setdefault(host, 0)
        risk_table[host] += 3

    # Malware points
    for f in malware_findings:
        host = f.get("host")
        risk_table.setdefault(host, 0)
        risk_table[host] += 5

    # Exfiltration points
    for f in exfiltration_findings:
        host = f.get("host", f.get("user"))
        risk_table.setdefault(host, 0)
        risk_table[host] += 7

    # Normalize and assign severity
    risk_results = []
    for host, points in risk_table.items():
        score = min(points / 15, 1.0)
        if score < 0.3:
            severity = "low"
        elif score < 0.6:
            severity = "medium"
        elif score < 0.8:
            severity = "high"
        else:
            severity = "critical"

        risk_results.append({
            "host": host,
            "score": round(score, 2),
            "severity": severity,
            "points": points
        })

    return risk_results
