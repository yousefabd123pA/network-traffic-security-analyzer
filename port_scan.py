class PortScanRule:
    def __init__(
        self,
        min_probes=50,         # Maps to tracker's "request_count"
        min_rate=5.0,          # Maps to tracker's "request_rate"
        max_inter_arrival=0.2, # Maps to tracker's "avg_inter_arrival"
        sustained_seconds=3.0  # Maps to tracker's "sustained_duration"
    ):
        self.min_probes = min_probes
        self.min_rate = min_rate
        self.max_inter_arrival = max_inter_arrival
        self.sustained_seconds = sustained_seconds

    # =========================================
    # INDIVIDUAL CLASSIFIERS
    # =========================================
    def _classify_probe_count(self, value):
        if value >= self.min_probes: return "Strong"
        if value >= self.min_probes * 0.7: return "Moderate"
        return "Weak"

    def _classify_scan_rate(self, value):
        if value >= self.min_rate: return "Strong"
        if value >= self.min_rate * 0.7: return "Moderate"
        return "Weak"

    def _classify_inter_arrival(self, value):
        if value <= 0: return "Weak" if value < 0 else "Strong"
        if value <= self.max_inter_arrival: return "Strong"
        if value <= self.max_inter_arrival * 2: return "Moderate"
        return "Weak"

    def _classify_sustained_duration(self, value):
        if value >= self.sustained_seconds: return "Strong"
        if value >= self.sustained_seconds * 0.7: return "Moderate"
        return "Weak"

    # =========================================
    # GROUP AGGREGATION & DESCRIPTION
    # =========================================
    def _classify_group(self, indicators):
        strong = sum(level == "Strong" for level in indicators.values())
        moderate = sum(level == "Moderate" for level in indicators.values())
        
        if strong >= 2: return "Strong"
        if strong >= 1 or moderate >= 1: return "Moderate"
        return "Weak"

    def _describe_group(self, group, level):
        descriptions = {
            "volume": {
                "Weak": "Low Probe Volume",
                "Moderate": "Elevated Probe Volume",
                "Strong": "High Probe Volume"
            },
            "intensity": {
                "Weak": "Low Scan Speed",
                "Moderate": "Elevated Scan Speed",
                "Strong": "High Scan Speed"
            },
            "persistence": {
                "Weak": "Brief Activity",
                "Moderate": "Sustained Activity",
                "Strong": "Highly Sustained Activity"
            }
        }
        return descriptions[group][level]

    # =========================================
    # MAIN DETECTION LOGIC
    # =========================================
    def detect(self, features):
        # Extract features EXACTLY as output by 3_tracker.py
        probe_count = features.get("request_count", 0)
        scan_rate = features.get("request_rate", 0.0)
        avg_inter_arrival = features.get("avg_inter_arrival", 0.0)
        sustained_duration = features.get("sustained_duration", 0.0)

        # 1. Evaluate indicators by category
        volume = {
            "probe_count": self._classify_probe_count(probe_count)
        }
        intensity = {
            "scan_rate": self._classify_scan_rate(scan_rate),
            "avg_inter_arrival": self._classify_inter_arrival(avg_inter_arrival)
        }
        persistence = {
            "sustained_duration": self._classify_sustained_duration(sustained_duration)
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
            attack = "Port Scan"
            severity = "High"
        elif (strong_groups >= 1 and moderate_groups >= 1) or moderate_groups >= 3:
            detected = True
            attack = "Possible Port Scan"
            severity = "Medium"
        elif strong_groups == 1 or moderate_groups >= 2:
            detected = True
            attack = "Suspicious Scanning Activity"
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