class AlertManager:

    def __init__(self):

        self.alerts = []
        self.alert_counter = 0

    def create_alert(self, detection):

        if detection is None:
            return None

        # لا يتم إنشاء Alert للـ NORMAL
        if not detection.get("alert", False):
            return None

        self.alert_counter += 1

        alert_id = f"ALT-{self.alert_counter:04d}"

        alert = {
            "alert_id": alert_id,
            "source_ip": detection.get("source_ip"),
            "status": detection.get("status"),
            "window_count": detection.get(
                "window_count",
                0
            ),
            "attack": detection.get("attack"),
            "severity": detection.get("severity"),
            "detected": detection.get(
                "detected",
                False
            ),
            "alert_status": "ACTIVE"
        }

        self.alerts.append(alert)

        return alert

    def get_all(self):
        return self.alerts

    def get_active_alerts(self):

        return [
            alert
            for alert in self.alerts
            if alert["alert_status"] == "ACTIVE"
        ]

    def clear(self):

        self.alerts.clear()
        self.alert_counter = 0