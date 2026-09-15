from collections import defaultdict, deque


class HTTPRequestTracker:

    def __init__(
        self,
        window_seconds=10,
        continuity_gap=0.1
    ):
        self.window_seconds = window_seconds
        self.continuity_gap = continuity_gap

        self.requests = defaultdict(deque)
        self.window_start = {}

    def add_request(self, source_ip, timestamp):
        request_times = self.requests[source_ip]

        if source_ip not in self.window_start:
            self.window_start[source_ip] = timestamp

        window_start = self.window_start[source_ip]

        request_times.append(timestamp)

        window_elapsed = timestamp - window_start

        if window_elapsed >= self.window_seconds:
            features = self._calculate_features(
                request_times
            )

            self.window_start[source_ip] = timestamp

            request_times.clear()
            request_times.append(timestamp)

            features["new_window"] = True

        else:
            features = self._calculate_features(
                request_times
            )

            features["new_window"] = False

        return features

    def finalize(self, source_ip):
        if source_ip not in self.requests:
            return None

        request_times = self.requests[source_ip]

        if not request_times:
            return None

        features = self._calculate_features(
            request_times
        )

        features["new_window"] = True
        features["final_window"] = True

        request_times.clear()

        self.window_start.pop(
            source_ip,
            None
        )

        return features

    def _calculate_features(self, request_times):
        if not request_times:
            return {
                "request_count": 0,
                "request_rate": 0,
                "average_inter_arrival": 0,
                "sustained_duration": 0,
                "continuous_requests": 0
            }

        request_count = len(request_times)

        if request_count > 1:
            duration = (
                request_times[-1]
                - request_times[0]
            )

            if duration > 0:
                request_rate = (
                    request_count / duration
                )
            else:
                request_rate = 0
        else:
            request_rate = 0

        intervals = [
            request_times[i]
            - request_times[i - 1]
            for i in range(1, request_count)
        ]

        if intervals:
            average_inter_arrival = (
                sum(intervals)
                / len(intervals)
            )
        else:
            average_inter_arrival = 0

        continuous_start = request_times[-1]
        continuous_requests = 1

        for i in range(
            request_count - 1,
            0,
            -1
        ):
            interval = (
                request_times[i]
                - request_times[i - 1]
            )

            if interval <= self.continuity_gap:
                continuous_start = (
                    request_times[i - 1]
                )
                continuous_requests += 1
            else:
                break

        sustained_duration = (
            request_times[-1]
            - continuous_start
        )

        return {
            "request_count": request_count,
            "request_rate": request_rate,
            "average_inter_arrival": (
                average_inter_arrival
            ),
            "sustained_duration": (
                sustained_duration
            ),
            "continuous_requests": (
                continuous_requests
            )
        }