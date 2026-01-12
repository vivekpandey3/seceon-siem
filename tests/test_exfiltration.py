from tools.detections.exfiltration import detect

def test_exfiltration_detected():
    logs = [
        {
            "timestamp": "2026-01-12T23:30:00",
            "user": "alice",
            "destination_ip": "8.8.8.8",
            "bytes_sent": 150_000_000
        }
    ]

    result = detect(logs)

    assert result["total"] == 1
    assert result["findings"][0]["type"] == "exfiltration"
    assert result["findings"][0]["user"] == "alice"
    assert result["findings"][0]["bytes_sent"] >= 150_000_000
