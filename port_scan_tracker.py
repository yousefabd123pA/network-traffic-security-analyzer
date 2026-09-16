from collections import defaultdict

class PortScanTracker:
    """
    Tracks per-source-IP unique destination ports in rolling windows for Port Scan detection.
    """
    def __init__(self, window_seconds=10, required_streak=3):
        self.window_seconds = window_seconds
        self.required_streak = required_streak
        
        self.dst_ports = defaultdict(set)
        self.packet_counts = defaultdict(int)
        self.window_start = {}
        self.streaks = defaultdict(int)

    def process_packet(self, source_ip, packet):
        dst_port = packet.get("dst_port")
        if dst_port is None:
            return None
            
        timestamp = packet.get("timestamp")
        if timestamp is None:
            return None

        if source_ip not in self.window_start:
            self.window_start[source_ip] = timestamp

        self.dst_ports[source_ip].add(dst_port)
        self.packet_counts[source_ip] += 1
        
        window_elapsed = timestamp - self.window_start[source_ip]

        if window_elapsed >= self.window_seconds:
            features = self._calculate_features(source_ip)
            self.window_start[source_ip] = timestamp
            self.dst_ports[source_ip].clear()
            self.packet_counts[source_ip] = 0
            
            # Add current packet to the new window
            self.dst_ports[source_ip].add(dst_port)
            self.packet_counts[source_ip] = 1
            features["new_window"] = True
        else:
            features = self._calculate_features(source_ip)
            features["new_window"] = False

        return features

    def finalize(self, source_ip):
        if source_ip not in self.dst_ports:
            return None
        if not self.dst_ports[source_ip]:
            return None
        
        features = self._calculate_features(source_ip)
        features["new_window"] = True
        features["final_window"] = True
        self.dst_ports[source_ip].clear()
        self.packet_counts[source_ip] = 0
        self.window_start.pop(source_ip, None)
        return features

    def update_streak(self, source_ip, is_attack):
        if is_attack:
            self.streaks[source_ip] += 1
        else:
            self.streaks[source_ip] = 0
        return self.streaks[source_ip]

    def get_streak(self, source_ip):
        return self.streaks.get(source_ip, 0)

    def is_confirmed(self, source_ip):
        return self.get_streak(source_ip) >= self.required_streak

    def _calculate_features(self, source_ip):
        streak = self.get_streak(source_ip)
        unique_ports = len(self.dst_ports[source_ip])
        count = self.packet_counts[source_ip]
        
        scan_rate = unique_ports / self.window_seconds if self.window_seconds > 0 else 0
        
        return {
            "unique_dst_ports": unique_ports,
            "scan_rate": scan_rate,
            "total_packets": count,
            "streak": streak,
            "required_streak": self.required_streak,
            "attack_confirmed": streak >= self.required_streak
        }