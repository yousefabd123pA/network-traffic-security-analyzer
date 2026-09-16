class ReportGenerator:

    def __init__(self):
        self.reports = []

    def generate(self, alert, evidence):
        """
        Generate a human-readable security report.
        """

        if alert is None or evidence is None:
            return None

        source_ip = evidence.get(
            "source_ip",
            "Unknown"
        )

        attack = evidence.get(
            "attack",
            "Unknown"
        )

        severity = evidence.get(
            "severity",
            "Unknown"
        )

        score = evidence.get(
            "score",
            0
        )

        request_count = evidence.get(
            "request_count",
            0
        )

        request_rate = evidence.get(
            "request_rate",
            0
        )

        average_inter_arrival = evidence.get(
            "average_inter_arrival",
            0
        )

        sustained_duration = evidence.get(
            "sustained_duration",
            0
        )

        continuous_requests = evidence.get(
            "continuous_requests",
            0
        )

        attack_confirmed = evidence.get(
            "attack_confirmed",
            False
        )

        reason = evidence.get(
            "reason",
            "No additional evidence available."
        )

        confirmation_text = (
            "The attack was confirmed after "
            "remaining suspicious across "
            "multiple consecutive analysis windows."
            if attack_confirmed
            else
            "The activity was detected as suspicious "
            "but has not been confirmed."
        )

        report = (
            f"HTTP Flood detected from {source_ip}. "

            f"The source generated {request_count} "
            f"HTTP requests during the analysis window, "
            f"with an average request rate of "
            f"{request_rate:.2f} requests per second. "

            f"The average time between requests was "
            f"{average_inter_arrival:.4f} seconds, "
            f"while the traffic remained active for "
            f"{sustained_duration:.2f} seconds. "

            f"A total of {continuous_requests} requests "
            f"were observed as part of the continuous "
            f"request stream. "

            f"The detection engine assigned a suspicion "
            f"score of {score}/5 and classified the "
            f"activity as {severity} severity. "

            f"Observed indicators were: {reason}. "

            f"{confirmation_text}"
        )

        result = {
            "report": report,
            "alert_id": alert.get(
                "alert_id"
            ),
            "attack": attack,
            "severity": severity,
            "confirmed": attack_confirmed
        }

        self.reports.append(result)

        return result

    def get_all_reports(self):
        """
        Return all generated reports.
        """

        return self.reports

    def clear(self):
        """
        Clear generated reports.
        """

        self.reports.clear()
