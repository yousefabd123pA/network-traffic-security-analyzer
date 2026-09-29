class HTTPFloodRule:

    def __init__(
        self,
        min_requests=100,
        min_rate=40,
        max_inter_arrival=0.05
    ):
        self.min_requests = min_requests
        self.min_rate = min_rate
        self.max_inter_arrival = max_inter_arrival

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
            return "Weak"

        if value <= self.max_inter_arrival:
            return "Strong"

        if value <= self.max_inter_arrival * 2:
            return "Moderate"

        return "Weak"

    # =========================================
    # GROUP AGGREGATION
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

        # All indicators are Strong
        if strong == len(indicators):
            return "Strong"

        # At least one Strong indicator
        if strong >= 1:
            return "Moderate"

        # Multiple Moderate indicators
        if moderate >= 2:
            return "Moderate"

        # One Moderate indicator
        if moderate >= 1:
            return "Moderate"

        return "Weak"

    # =========================================
    # GROUP DESCRIPTION
    # =========================================

    def _describe_group(self, group, level):

        descriptions = {

            "volume": {

                "Weak":
                    "Low Traffic Volume",

                "Moderate":
                    "Elevated Traffic Volume",

                "Strong":
                    "High Traffic Volume"
            },

            "intensity": {

                "Weak":
                    "Low Request Intensity",

                "Moderate":
                    "Elevated Request Intensity",

                "Strong":
                    "High Request Intensity"
            }
        }

        return descriptions[group][level]

    # =========================================
    # MAIN DETECTION LOGIC
    # =========================================

    def detect(self, features):

        request_count = features.get(
            "request_count",
            0
        )

        request_rate = features.get(
            "request_rate",
            0.0
        )

        avg_inter_arrival = features.get(
            "avg_inter_arrival",
            0.0
        )

        # =========================================
        # 1. Individual Indicators
        # =========================================

        volume = {

            "request_count":
                self._classify_request_count(
                    request_count
                )
        }

        intensity = {

            "request_rate":
                self._classify_request_rate(
                    request_rate
                ),

            "avg_inter_arrival":
                self._classify_inter_arrival(
                    avg_inter_arrival
                )
        }

        # =========================================
        # 2. Group Strength
        # =========================================

        volume_level = self._classify_group(
            volume
        )

        intensity_level = self._classify_group(
            intensity
        )

        # =========================================
        # 3. Descriptions
        # =========================================

        volume_description = self._describe_group(
            "volume",
            volume_level
        )

        intensity_description = self._describe_group(
            "intensity",
            intensity_level
        )

        # =========================================
        # 4. Overall Evidence
        # =========================================

        levels = [
            volume_level,
            intensity_level
        ]

        strong_groups = sum(
            level == "Strong"
            for level in levels
        )

        moderate_groups = sum(
            level == "Moderate"
            for level in levels
        )

        # =========================================
        # 5. Final Status
        # =========================================

        # -----------------------------------------
        # Strong + Strong
        # -----------------------------------------

        if strong_groups == 2:

            status = "DETECTED"
            detected = True
            alert = True

            attack = "HTTP Flood"
            severity = "High"

        # -----------------------------------------
        # Strong + Moderate
        # Moderate + Strong
        # -----------------------------------------

        elif (
            strong_groups >= 1
            and moderate_groups >= 1
        ):

            status = "DETECTED"
            detected = True
            alert = True

            attack = "HTTP Flood"
            severity = "Medium"

        # -----------------------------------------
        # Strong + Weak
        # Weak + Strong
        # Moderate + Moderate
        # -----------------------------------------

        elif (
            strong_groups == 1
            or moderate_groups == 2
        ):

            status = "ATTENTION"
            detected = False
            alert = True

            attack = "Suspicious HTTP Activity"
            severity = "Low"

        # -----------------------------------------
        # Moderate + Weak
        # Weak + Moderate
        # Weak + Weak
        # -----------------------------------------

        else:

            status = "NORMAL"
            detected = False
            alert = False

            attack = None
            severity = "Informational"

        # =========================================
        # 6. Final Result
        # =========================================

        return {

            "status":
                status,

            "alert":
                alert,

            "detected":
                detected,

            "attack":
                attack,

            "severity":
                severity,

            "volume":
                volume,

            "intensity":
                intensity,

            "assessment": {

                "volume":
                    volume_description,

                "intensity":
                    intensity_description
            },

            "group_strength": {

                "volume":
                    volume_level,

                "intensity":
                    intensity_level
            },

            "strong_groups":
                strong_groups,

            "moderate_groups":
                moderate_groups
        }