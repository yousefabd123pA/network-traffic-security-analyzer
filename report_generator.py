class ReportGenerator:

    def __init__(self):
        self.reports = []

    # =========================================================
    # BUILD INCIDENT STORY
    # =========================================================

    def _build_narrative(
        self,
        attack,
        request_count,
        status,
        severity,
        sustained_duration
    ):

        if status == "ATTENTION":
            return (
                f"Suspicious HTTP traffic was detected "
                f"from the identified source. "
                f"The traffic showed an unusual pattern "
                f"with repeated HTTP requests. "
                f"During the monitoring period, the source generated {request_count} "
                f"HTTP requests , producing a traffic "
                f"pattern that differs significantly from typical request behavior. "
                f"The activity lasted for approximately "
                f"{sustained_duration:.2f} seconds. "
                f"The available evidence indicates suspicious "
                f"activity that requires attention. "
                f"The activity was classified as ATTENTION "
                f"with {severity} severity."
            )

        return (
            f"An {attack} incident was detected involving abnormal HTTP traffic "
            f"originating from the identified source. "
            f"During the monitoring period, the source generated {request_count} "
            f"HTTP requests , producing a traffic "
            f"pattern that differs significantly from typical request behavior. "

            f"The detected activity persisted for approximately "
            f"{sustained_duration:.2f} seconds and maintained a continuous pattern "
            f"of HTTP requests during the observed period. "
            f"The high number of requests and the observed request activity "
            f"provide evidence of abnormal request generation from the identified source. "

            f"Based on the observed traffic, the activity is consistent with "
            f"an HTTP Flood attack and may indicate an attempt to overwhelm "
            f"the targeted service through excessive HTTP requests. "
            f"The incident was classified as {status} with {severity} severity "
            f"based on the observed behavior and supporting traffic evidence. "

            f"The identified source and associated traffic activity should be "
            f"reviewed as part of the incident investigation. "
            f"Additional analysis of the captured traffic may be required to "
            f"determine the full impact, duration, and scope of the event."
        )

    # =========================================================
    # GENERATE REPORT
    # =========================================================

    def generate(
        self,
        alert,
        detection,
        tracker_data=None
    ):

        if detection is None:
            return None

        status = detection.get(
            "status"
        )

        if status == "NORMAL":
            return None

        source_ip = detection.get(
            "source_ip",
            "Unknown"
        )

        attack = detection.get(
            "attack",
            "Suspicious HTTP Activity"
        )

        severity = detection.get(
            "severity",
            "Unknown"
        )

        request_count = detection.get(
            "request_count",
            0
        )

        sustained_duration = 0.0

        if tracker_data is not None:
            sustained_duration = tracker_data.get(
                "sustained_duration",
                0.0
            )

        narrative = self._build_narrative(
            attack,
            request_count,
            status,
            severity,
            sustained_duration
        )

        report = {
            "source_ip": source_ip,
            "attack": attack,
            "status": status,
            "severity": severity,
            "request_count": detection.get(
                "request_count",
                0
            ),
            "sustained_duration": sustained_duration,
            "narrative": narrative,
            "alert_id":
                alert.get("alert_id")
                if alert
                else None
        }

        self.reports.append(
            report
        )

        return report

    # =========================================================
    # GET ALL REPORTS
    # =========================================================

    def get_all_reports(self):

        return self.reports

    # =========================================================
    # CLEAR
    # =========================================================

    def clear(self):

        self.reports.clear()