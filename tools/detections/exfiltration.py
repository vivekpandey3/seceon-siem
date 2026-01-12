def detect(logs, page=1, page_size=50):
    findings = []

    for log in logs:
        bytes_sent = log.get("bytes_sent", 0)

        # Rule: anything >= 100MB is suspicious
        if bytes_sent >= 100_000_000:
            findings.append({
                "type": "exfiltration",
                "user": log.get("user"),
                "destination_ip": log.get("destination_ip"),
                "bytes_sent": bytes_sent,
                "timestamp": log.get("timestamp")
            })

    start = (page - 1) * page_size
    end = start + page_size

    return {
        "total": len(findings),
        "page": page,
        "page_size": page_size,
        "findings": findings[start:end]
    }
