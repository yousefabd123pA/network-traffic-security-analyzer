class HTTPFloodRule:

    def __init__(
        self,
        min_requests=100,
        min_rate=40,
        max_inter_arrival=0.05,
        sustained_seconds=5
    ):
        self.min_requests = min_requests
        self.min_rate = min_rate
        self.max_inter_arrival = max_inter_arrival
        self.sustained_seconds = sustained_seconds

    # =========================================
    # INDIVIDUAL CLASSIFIERS
    # =========================================

    def _classify_request_count(self, value):
        if value >= self.min_requests:
            return "Strong"
        if value >= self.min_requests * 0.8:
            return "Moderate"
        return "Weak"

    def _classify_request_rate(self, value):
        if value >= self.min_rate:
            return "Strong"
        if value >= self.min_rate * 0.8:
            return "Moderate"
        return "Weak"

    def _classify_inter_arrival(self, value):
        if value <= 0:
            return "Weak" if value < 0 else "Strong"
        if value <= self.max_inter_arrival:
            return "Strong"
        if value <= self.max_inter_arrival * 2:
            return "Moderate"
        return "Weak"

    def _classify_sustained_duration(self, value):
        if value >= self.sustained_seconds:
            return "Strong"
        if value >= self.sustained_seconds * 0.8:
            return "Moderate"
        return "Weak"

    def _classify_continuous_requests(self, value):
        if value >= self.min_requests:
            return "Strong"
        if value >= self.min_requests * 0.8:
            return "Moderate"
        return "Weak"

    def _classify_streak(self, value):
        if value >= 3:
            return "Strong"
        if value >= 2:
            return "Moderate"
        return "Weak"

    # =========================================
    # GROUP AGGREGATION & DESCRIPTION
    # =========================================

    def _classify_group(self, indicators):
        strong = sum(
            level == "Strong"
            for level in indicators.values()
        )
        moderate = sum(
            level == "Moderate"
            for level in indicators.values()
        )

        if strong >= 2:
            return "Strong"
        if strong >= 1 or moderate >= 1:
            return "Moderate"
        return "Weak"

    def _describe_group(self, group, level):
        descriptions = {
            "volume": {
                "Weak": "Low Traffic Volume",
                "Moderate": "Elevated Traffic Volume",
                "Strong": "High Traffic Volume"
            },
            "intensity": {
                "Weak": "Low Request Intensity",
                "Moderate": "Elevated Request Intensity",
                "Strong": "High Request Intensity"
            },
            "persistence": {
                "Weak": "Low Persistence",
                "Moderate": "Sustained Persistence",
                "Strong": "High Persistence"
            }
        }
        return descriptions[group][level]

    # =========================================
    # MAIN DETECTION LOGIC
    # =========================================

    def detect(self, features):

        request_count = features.get("request_count", 0)
        request_rate = features.get("request_rate", 0.0)
        avg_inter_arrival = features.get("avg_inter_arrival", 0.0)
        sustained_duration = features.get("sustained_duration", 0.0)
        continuous_requests = features.get("continuous_requests", 0)
        streak = features.get("streak", 0)

        # 1. Evaluate indicators by category
        volume = {
            "request_count": self._classify_request_count(request_count),
            "continuous_requests": self._classify_continuous_requests(continuous_requests)
        }

        intensity = {
            "request_rate": self._classify_request_rate(request_rate),
            "avg_inter_arrival": self._classify_inter_arrival(avg_inter_arrival)
        }

        persistence = {
            "sustained_duration": self._classify_sustained_duration(sustained_duration),
            "streak": self._classify_streak(streak)
        }

        # 2. Evaluate strength per category
        volume_level = self._classify_group(volume)
        intensity_level = self._classify_group(intensity)
        persistence_level = self._classify_group(persistence)

        volume_description = self._describe_group("volume", volume_level)
        intensity_description = self._describe_group("intensity", intensity_level)
        persistence_description = self._describe_group("persistence", persistence_level)

        levels = [volume_level, intensity_level, persistence_level]

        strong_groups = sum(level == "Strong" for level in levels)
        moderate_groups = sum(level == "Moderate" for level in levels)

        # 3. Flexible Multi-Evidence Decision Logic
        if strong_groups >= 2:
            detected = True
            attack = "HTTP Flood"
            severity = "High"

        elif (strong_groups >= 1 and moderate_groups >= 1) or moderate_groups >= 3:
            detected = True
            attack = "Possible HTTP Flood"
            severity = "Medium"

        elif strong_groups == 1 or moderate_groups >= 2:
            detected = True
            attack = "Suspicious HTTP Activity"
            severity = "Low"

        else:
            detected = False
            attack = None
            severity = "Informational"

        return {
            "detected": detected,
            "attack": attack,
            "severity": severity,
            "volume": volume,
            "intensity": intensity,
            "persistence": persistence,
            "assessment": {
                "volume": volume_description,
                "intensity": intensity_description,
                "persistence": persistence_description
            },
            "group_strength": {
                "volume": volume_level,
                "intensity": intensity_level,
                "persistence": persistence_level
            },
            "strong_groups": strong_groups,
            "moderate_groups": moderate_groups
        }
