from tools.detections.brute_force import detect

def test_brute_force_detected():
    logs = [
        {"timestamp": "2026-01-12T10:00:01", "source_ip": "10.0.0.5", "user": "admin", "event_type": "login_failed"},
        {"timestamp": "2026-01-12T10:00:10", "source_ip": "10.0.0.5", "user": "admin", "event_type": "login_failed"},
        {"timestamp": "2026-01-12T10:00:20", "source_ip": "10.0.0.5", "user": "admin", "event_type": "login_failed"},
        {"timestamp": "2026-01-12T10:00:30", "source_ip": "10.0.0.5", "user": "admin", "event_type": "login_failed"},
        {"timestamp": "2026-01-12T10:00:40", "source_ip": "10.0.0.5", "user": "admin", "event_type": "login_failed"},
    ]

    result = detect(logs)

    assert result["total"] == 1
    assert result["findings"][0]["type"] == "brute_force"
    assert result["findings"][0]["source_ip"] == "10.0.0.5"
    assert result["findings"][0]["user"] == "admin"
