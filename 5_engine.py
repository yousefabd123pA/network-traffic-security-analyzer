from trackers.http_tracker import HTTPRequestTracker
from rules.http_flood import HTTPFloodRule


class DetectionEngine:

    def __init__(self):

        self.http_tracker = HTTPRequestTracker(
            window_seconds=10,
            continuity_gap=0.1
        )

        self.http_flood_rule = HTTPFloodRule(
            min_requests=100,
            min_rate=40,
            max_inter_arrival=0.05,
            sustained_seconds=5
        )

    # =========================================
    # PROCESS SINGLE PACKET
    # =========================================

    def process_packet(self, packet):

        # -----------------------------------------
        # Ignore non-HTTP / non-Request traffic
        # -----------------------------------------

        if packet.get("application") != "HTTP" or packet.get("http_method") is None:
            return None

        source_ip = packet.get("src_ip")
        timestamp = packet.get("timestamp")

        if source_ip is None or timestamp is None:
            return None

        # -----------------------------------------
        # Update tracker (includes historic streak in features)
        # -----------------------------------------

        features = self.http_tracker.add_request(
            source_ip,
            timestamp
        )

        # -----------------------------------------
        # New analysis window completed
        # -----------------------------------------

        if features["new_window"]:

            # 1. Single Evaluation using window features + historic streak
            rule_detection = self.http_flood_rule.detect(features)

            # 2. Update Tracker's streak state for FUTURE windows
            is_attack = rule_detection["detected"]
            self.http_tracker.update_streak(source_ip, is_attack)

            # 3. Format detection output
            detection = {
                "detected": rule_detection["detected"],
                "attack": rule_detection["attack"],
                "severity": rule_detection["severity"],
                "volume": rule_detection["volume"],
                "intensity": rule_detection["intensity"],
                "persistence": rule_detection["persistence"],
                "assessment": rule_detection["assessment"],
                "group_strength": rule_detection["group_strength"],
                "strong_groups": rule_detection["strong_groups"],
                "moderate_groups": rule_detection["moderate_groups"]
            }

        # -----------------------------------------
        # Still inside current active window
        # -----------------------------------------

        else:

            detection = {
                "detected": False,
                "attack": None,
                "severity": "None",
                "volume": None,
                "intensity": None,
                "persistence": None,
                "assessment": None,
                "group_strength": None,
                "strong_groups": 0,
                "moderate_groups": 0
            }

        # -----------------------------------------
        # Final result structure
        # -----------------------------------------

        return {
            "source_ip": source_ip,
            "timestamp": timestamp,
            "http_method": packet.get("http_method"),
            "features": features,
            "detection": detection,
            "persistence": {
                "suspicious_streak": features.get("streak", 0)
            }
        }

    # =========================================
    # FINALIZE ALL TRACKERS (Call at end of PCAP)
    # =========================================

    def finalize_ip(self, source_ip):

        features = self.http_tracker.finalize(source_ip)

        if not features:
            return None

        rule_detection = self.http_flood_rule.detect(features)

        is_attack = rule_detection["detected"]
        self.http_tracker.update_streak(source_ip, is_attack)

        return {
            "source_ip": source_ip,
            "features": features,
            "detection": rule_detection
        }
