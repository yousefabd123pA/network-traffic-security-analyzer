from collections import defaultdict, deque
from typing import Any, Dict, List, Optional


class HTTPRequestTracker:
    """Tracks HTTP request rates and inter-arrival metrics using a sliding window."""

    def __init__(self, window_seconds: float = 10.0, min_window_duration: float = 5.0) -> None:
        self.window_seconds = window_seconds
        self.min_window_duration = min_window_duration

        # Used for sliding-window metrics
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.output_requests: Dict[str, deque] = defaultdict(deque)
        self.period_start: Dict[str, Optional[float]] = defaultdict(lambda: None)

        # Used ONLY for full attack duration
        self.attack_start: Dict[str, Optional[float]] = defaultdict(lambda: None)
        self.attack_end: Dict[str, Optional[float]] = defaultdict(lambda: None)

    def _calculate_metrics(
        self,
        src_ip: str,
        timestamps: deque,
        window_start: float,
        window_end: float,
    ) -> Optional[Dict[str, Any]]:
        """Calculate statistical traffic metrics for a specific time window."""
        if not timestamps:
            return None

        window_duration = window_end - window_start
        if window_duration < self.min_window_duration:
            return None

        request_count = len(timestamps)

        # Request rate inside this window
        if len(timestamps) > 1:
            duration = timestamps[-1] - timestamps[0]
        else:
            duration = 0.0

        request_rate = (request_count / duration) if duration > 0 else 0.0

        # Average inter-arrival time inside this window
        if len(timestamps) > 1:
            intervals = [
                timestamps[i] - timestamps[i - 1]
                for i in range(1, len(timestamps))
            ]
            avg_inter_arrival = sum(intervals) / len(intervals)
        else:
            avg_inter_arrival = 0.0

        return {
            "src_ip": src_ip,
            "window_start": window_start,
            "window_end": window_end,
            "request_count": request_count,
            "request_rate": request_rate,
            "avg_inter_arrival": avg_inter_arrival,
        }

    def update(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update request logs with new packet data and return window metrics if window completes."""
        src_ip = packet["src_ip"]
        timestamp = packet["timestamp"]

        # ----------------------------------------
        # Full PCAP attack duration
        # ----------------------------------------
        if self.attack_start[src_ip] is None:
            self.attack_start[src_ip] = timestamp

        # Always keep the latest HTTP request timestamp
        self.attack_end[src_ip] = timestamp

        # ----------------------------------------
        # Window tracking
        # ----------------------------------------
        timestamps = self.requests[src_ip]
        timestamps.append(timestamp)

        cutoff = timestamp - self.window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        # ----------------------------------------
        # Output window tracking
        # ----------------------------------------
        output_requests = self.output_requests[src_ip]
        output_requests.append(timestamp)

        if self.period_start[src_ip] is None:
            self.period_start[src_ip] = timestamp
            return None

        if timestamp - self.period_start[src_ip] < self.window_seconds:
            return None

        window_start = self.period_start[src_ip]
        window_end = timestamp

        result = self._calculate_metrics(
            src_ip, output_requests, window_start, window_end
        )

        # Start a new window
        self.period_start[src_ip] = timestamp
        self.output_requests[src_ip] = deque([timestamp])

        return result

    def flush(self) -> List[Dict[str, Any]]:
        """Flush and process remaining buffered request windows."""
        outputs = []

        for src_ip, timestamps in self.output_requests.items():
            if not timestamps:
                continue

            window_start = self.period_start[src_ip]
            window_end = timestamps[-1]

            result = self._calculate_metrics(
                src_ip, timestamps, window_start, window_end
            )

            # ----------------------------------------
            # Full attack duration
            # ----------------------------------------
            sustained_duration = (
                self.attack_end[src_ip] - self.attack_start[src_ip]
            )

            if result is not None:
                result["sustained_duration"] = sustained_duration
                outputs.append(result)

            # ----------------------------------------
            # If the final window is too short,
            # preserve duration on previous output
            # ----------------------------------------
            elif outputs:
                outputs[-1]["sustained_duration"] = sustained_duration

            self.output_requests[src_ip].clear()

        return outputs

    def get_sustained_durations(self) -> Dict[str, float]:
        """Return total duration per source IP."""
        durations = {}
        for src_ip in self.attack_start:
            if (
                self.attack_start[src_ip] is not None
                and self.attack_end[src_ip] is not None
            ):
                durations[src_ip] = (
                    self.attack_end[src_ip] - self.attack_start[src_ip]
                )
        return durations