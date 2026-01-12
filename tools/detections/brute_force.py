from datetime import datetime, timedelta

def detect(logs, page=1, page_size=50):
    for log in logs:
        log['timestamp'] = datetime.fromisoformat(log['timestamp'])

    groups = {}
    for log in logs:
        if log['event_type'] != "login_failed":
            continue
        key = (log['source_ip'], log['user'])
        groups.setdefault(key, []).append(log['timestamp'])

    findings = []

    for (ip, user), timestamps in groups.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            count = 1
            for j in range(i+1, len(timestamps)):
                if (timestamps[j] - timestamps[i]).total_seconds() <= 120:
                    count += 1
                else:
                    break
            if count >= 5:
                findings.append({
                    "type": "brute_force",
                    "source_ip": ip,
                    "user": user,
                    "attempts": count,
                    "severity": "high" if count >= 10 else "medium",
                    "confidence": min(1.0, count/10)
                })
                break
    total = len(findings)
    start = (page-1)*page_size
    end = start + page_size
    paginated = findings[start:end]

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "findings": paginated
    }
