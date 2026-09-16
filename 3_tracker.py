from collections import defaultdict, deque


class HTTPRequestTracker:

    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds

        # timestamps لكل Source IP
        self.requests = defaultdict(deque)

    def update(self, packet):
        """
        packet = Parser output
        """

        src_ip = packet["src_ip"]
        timestamp = packet["timestamp"]

        # هات requests الخاصة بالـ IP
        timestamps = self.requests[src_ip]

        # ضيف الـ request الجديدة
        timestamps.append(timestamp)

        # Sliding Window
        cutoff = timestamp - self.window_seconds

        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        # 1. Request Count
        request_count = len(timestamps)

        # 2. Request Rate
        request_rate = request_count / self.window_seconds

        # 3. Average Inter-Arrival
        if len(timestamps) > 1:
            intervals = [
                timestamps[i] - timestamps[i - 1]
                for i in range(1, len(timestamps))
            ]

            avg_inter_arrival = sum(intervals) / len(intervals)
        else:
            avg_inter_arrival = 0.0

        # 4. Sustained Duration
        if len(timestamps) > 1:
            sustained_duration = timestamps[-1] - timestamps[0]
        else:
            sustained_duration = 0.0

        return {
            "src_ip": src_ip,
            "request_count": request_count,
            "request_rate": request_rate,
            "avg_inter_arrival": avg_inter_arrival,
            "sustained_duration": sustained_duration
        }