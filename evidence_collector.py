class EvidenceCollector:

    def __init__(self):
        self.evidence = []

    def collect(self, result):
        """
        Collect evidence from a detection engine result.
        """

        if result is None:
            return None

        detection = result.get("detection", {})
        features = result.get("features", {})
        persistence = result.get("persistence", {})

        # Ignore packets that did not produce a detection
        if not detection.get("detected", False):
            return None

        evidence = {
            "source_ip": result.get("source_ip"),
            "timestamp": result.get("timestamp"),

            "attack": detection.get("attack"),
            "severity": detection.get("severity"),

            "score": detection.get("score"),
            "reason": detection.get("reason"),

            "request_count": features.get(
                "request_count"
            ),

            "request_rate": features.get(
                "request_rate"
            ),

            "average_inter_arrival": features.get(
                "average_inter_arrival"
            ),

            "sustained_duration": features.get(
                "sustained_duration"
            ),

            "continuous_requests": features.get(
                "continuous_requests"
            ),

            "suspicious_streak": persistence.get(
                "suspicious_streak"
            ),

            "required_streak": persistence.get(
                "required_streak"
            ),

            "attack_confirmed": persistence.get(
                "attack_confirmed"
            )
        }

        self.evidence.append(evidence)

        return evidence

    def get_all(self):
        """
        Return all collected evidence.
        """

        return self.evidence

    def clear(self):
        """
        Clear collected evidence.
        """

        self.evidence.clear()