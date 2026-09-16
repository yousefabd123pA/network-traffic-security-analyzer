from evidence.evidence_collector import EvidenceCollector
from alerts.alert_manager import AlertManager


print()
print("========== EVIDENCE + ALERT TEST ==========")
print()


# =========================================
# Fake Detection Engine Result
# =========================================

detection_result = {

    "source_ip": "172.29.16.1",

    "timestamp": 1787497132.779795,

    "http_method": "GET",

    "features": {

        "request_count": 462,

        "request_rate": 46.17,

        "average_inter_arrival": 0.0217,

        "sustained_duration": 10.00,

        "continuous_requests": 462
    },

    "detection": {

        "detected": True,

        "attack": "HTTP Flood",

        "severity": "High",

        "score": 5,

        "reason":
            "High request count; "
            "High request rate; "
            "Very fast request intervals; "
            "Sustained traffic; "
            "Continuous request stream"
    },

    "persistence": {

        "suspicious_streak": 3,

        "required_streak": 3,

        "attack_confirmed": True
    }
}


# =========================================
# Evidence Collector
# =========================================

collector = EvidenceCollector()

evidence = collector.collect(
    detection_result
)


print("========== EVIDENCE ==========")
print()

print(
    f"Source IP: "
    f"{evidence['source_ip']}"
)

print(
    f"Attack: "
    f"{evidence['attack']}"
)

print(
    f"Severity: "
    f"{evidence['severity']}"
)

print(
    f"Score: "
    f"{evidence['score']}"
)

print(
    f"Request Count: "
    f"{evidence['request_count']}"
)

print(
    f"Request Rate: "
    f"{evidence['request_rate']}"
)

print(
    f"Confirmed: "
    f"{evidence['attack_confirmed']}"
)


# =========================================
# Alert Manager
# =========================================

alert_manager = AlertManager()

alert = alert_manager.create_alert(
    evidence
)


print()
print("========== ALERT ==========")
print()

print(
    f"Alert ID: "
    f"{alert['alert_id']}"
)

print(
    f"Attack: "
    f"{alert['attack']}"
)

print(
    f"Severity: "
    f"{alert['severity']}"
)

print(
    f"Score: "
    f"{alert['score']}"
)

print(
    f"Confirmed: "
    f"{alert['confirmed']}"
)

print(
    f"Status: "
    f"{alert['status']}"
)


print()
print("========== TEST COMPLETE ==========")
