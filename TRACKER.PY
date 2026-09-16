from collections import defaultdict, deque

class TrafficTracker:
    """
    Unified tracker for HTTP Flood, SYN Flood, ICMP Flood, and Port Scanning.
    Tracks per-source-IP traffic in rolling windows and maintains cross-window 
    "suspicious streaks" for persistence-based attack confirmation.
    """
    def __init__(
        self,
        window_seconds=10,
        continuity_gap=0.1,
        required_streak=3
    ):
        self.window_seconds = window_seconds
        self.continuity_gap = continuity_gap
        self.required_streak = required_streak
        
        # Per source IP tracking state
        self.data = defaultdict(lambda: {
            'http_times': deque(),
            'syn_times': deque(),
            'icmp_times': deque(),
            'dst_ports': set(),       # For Port Scanning detection
            'total_packets': 0,
            'window_start': None,
            'streaks': defaultdict(int) # Tracks streaks per attack type
        })

    # =========================================
    # PACKET PROCESSING
    # =========================================
    def process_packet(self, source_ip, packet):
        """
        Process a parsed packet dictionary and update tracking state.
        Returns features dict when a window completes, otherwise returns None.
        """
        ip_data = self.data[source_ip]
        timestamp = packet.get('timestamp')
        
        if timestamp is None:
            return None

        if ip_data['window_start'] is None:
            ip_data['window_start'] = timestamp

        window_elapsed = timestamp - ip_data['window_start']
        
        # -----------------------------------------
        # Categorize Packet
        # -----------------------------------------
        is_http = (packet.get('application') == 'HTTP' and 
                   packet.get('http_method') is not None)
        
        flags = str(packet.get('flags', ''))
        # Pure SYN packet (S is present, A is not)
        is_syn = (packet.get('protocol') == 'TCP' and 
                  'S' in flags and 'A' not in flags)
                  
        is_icmp = packet.get('protocol') == 'ICMP'
        dst_port = packet.get('dst_port')

        # Add to respective queues/sets
        if is_http:
            ip_data['http_times'].append(timestamp)
        if is_syn:
            ip_data['syn_times'].append(timestamp)
        if is_icmp:
            ip_data['icmp_times'].append(timestamp)
        if dst_port is not None:
            ip_data['dst_ports'].add(dst_port)
            
        ip_data['total_packets'] += 1

        new_window = False
        features = None

        # -----------------------------------------
        # Window Evaluation
        # -----------------------------------------
        if window_elapsed >= self.window_seconds:
            new_window = True
            
            # Calculate features for the completed window
            http_feats = self._calculate_time_features(ip_data['http_times'])
            syn_feats = self._calculate_time_features(ip_data['syn_times'])
            icmp_feats = self._calculate_time_features(ip_data['icmp_times'])
            
            unique_ports = len(ip_data['dst_ports'])
            
            features = {
                # HTTP Flood Features
                "http_request_count": http_feats["count"],
                "http_request_rate": http_feats["rate"],
                "http_avg_inter_arrival": http_feats["avg_inter_arrival"],
                "http_sustained_duration": http_feats["sustained_duration"],
                "http_continuous_requests": http_feats["continuous_requests"],
                
                # SYN Flood Features
                "syn_count": syn_feats["count"],
                "syn_rate": syn_feats["rate"],
                "syn_avg_inter_arrival": syn_feats["avg_inter_arrival"],
                "syn_sustained_duration": syn_feats["sustained_duration"],
                "syn_continuous_requests": syn_feats["continuous_requests"],
                
                # ICMP Flood Features
                "icmp_count": icmp_feats["count"],
                "icmp_rate": icmp_feats["rate"],
                "icmp_avg_inter_arrival": icmp_feats["avg_inter_arrival"],
                "icmp_sustained_duration": icmp_feats["sustained_duration"],
                "icmp_continuous_requests": icmp_feats["continuous_requests"],
                
                # Port Scanning Features
                "unique_dst_ports": unique_ports,
                "scan_rate": unique_ports / self.window_seconds if self.window_seconds > 0 else 0,
                "total_packets": ip_data['total_packets'],
                
                # Streaks & Meta
                "streaks": dict(ip_data['streaks']),
                "required_streak": self.required_streak,
                "new_window": True
            }
            
            # Reset window state
            ip_data['window_start'] = timestamp
            ip_data['http_times'].clear()
            ip_data['syn_times'].clear()
            ip_data['icmp_times'].clear()
            ip_data['dst_ports'].clear()
            ip_data['total_packets'] = 0
            
            # Add current packet to the new window
            if is_http: ip_data['http_times'].append(timestamp)
            if is_syn: ip_data['syn_times'].append(timestamp)
            if is_icmp: ip_data['icmp_times'].append(timestamp)
            if dst_port is not None: ip_data['dst_ports'].add(dst_port)
            ip_data['total_packets'] += 1
        else:
            features = {"new_window": False}

        return features

    # =========================================
    # FINALIZE (End of PCAP)
    # =========================================
    def finalize(self, source_ip):
        if source_ip not in self.data:
            return None
            
        ip_data = self.data[source_ip]
        if ip_data['total_packets'] == 0:
            return None
            
        http_feats = self._calculate_time_features(ip_data['http_times'])
        syn_feats = self._calculate_time_features(ip_data['syn_times'])
        icmp_feats = self._calculate_time_features(ip_data['icmp_times'])
        unique_ports = len(ip_data['dst_ports'])
        
        features = {
            "http_request_count": http_feats["count"],
            "http_request_rate": http_feats["rate"],
            "http_avg_inter_arrival": http_feats["avg_inter_arrival"],
            "http_sustained_duration": http_feats["sustained_duration"],
            "http_continuous_requests": http_feats["continuous_requests"],
            
            "syn_count": syn_feats["count"],
            "syn_rate": syn_feats["rate"],
            "syn_avg_inter_arrival": syn_feats["avg_inter_arrival"],
            "syn_sustained_duration": syn_feats["sustained_duration"],
            "syn_continuous_requests": syn_feats["continuous_requests"],
            
            "icmp_count": icmp_feats["count"],
            "icmp_rate": icmp_feats["rate"],
            "icmp_avg_inter_arrival": icmp_feats["avg_inter_arrival"],
            "icmp_sustained_duration": icmp_feats["sustained_duration"],
            "icmp_continuous_requests": icmp_feats["continuous_requests"],
            
            "unique_dst_ports": unique_ports,
            "scan_rate": unique_ports / self.window_seconds if self.window_seconds > 0 else 0,
            "total_packets": ip_data['total_packets'],
            
            "streaks": dict(ip_data['streaks']),
            "required_streak": self.required_streak,
            "new_window": True,
            "final_window": True
        }
        
        # Clear state
        ip_data['http_times'].clear()
        ip_data['syn_times'].clear()
        ip_data['icmp_times'].clear()
        ip_data['dst_ports'].clear()
        ip_data['total_packets'] = 0
        ip_data['window_start'] = None
        
        return features

    # =========================================
    # PERSISTENCE / STREAK TRACKING
    # =========================================
    def update_streak(self, source_ip, attack_type, is_attack):
        """
        Updates the consecutive-attack streak for a specific attack type.
        """
        if is_attack:
            self.data[source_ip]['streaks'][attack_type] += 1
        else:
            self.data[source_ip]['streaks'][attack_type] = 0
            
        return self.data[source_ip]['streaks'][attack_type]

    def get_streak(self, source_ip, attack_type):
        return self.data[source_ip]['streaks'].get(attack_type, 0)

    def is_confirmed(self, source_ip, attack_type):
        return self.get_streak(source_ip, attack_type) >= self.required_streak

    # =========================================
    # FEATURE CALCULATION HELPER
    # =========================================
    def _calculate_time_features(self, times):
        if not times:
            return {
                "count": 0,
                "rate": 0.0,
                "avg_inter_arrival": 0.0,
                "sustained_duration": 0.0,
                "continuous_requests": 0
            }
            
        count = len(times)
        if count > 1:
            duration = times[-1] - times[0]
            rate = count / duration if duration > 0 else 0.0
        else:
            rate = 0.0
            
        intervals = [times[i] - times[i-1] for i in range(1, count)]
        avg_inter_arrival = sum(intervals) / len(intervals) if intervals else 0.0
        
        continuous_start = times[-1]
        continuous_count = 1
        for i in range(count - 1, 0, -1):
            if times[i] - times[i-1] <= self.continuity_gap:
                continuous_start = times[i-1]
                continuous_count += 1
            else:
                break
                
        sustained_duration = times[-1] - continuous_start
        
        return {
            "count": count,
            "rate": rate,
            "avg_inter_arrival": avg_inter_arrival,
            "sustained_duration": sustained_duration,
            "continuous_requests": continuous_count
        }