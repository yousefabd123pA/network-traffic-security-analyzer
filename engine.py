class DetectionEngine:

    def __init__(self, allowed_gap=10):

        self.allowed_gap = allowed_gap

        # State لكل Source IP
        self.states = {}

    def _calculate_severity(self, status, window_count):

        if status == "DETECTED":

            if window_count >= 3:
                return "Critical"

            if window_count == 2:
                return "High"

            return "Medium"

        if status == "ATTENTION":
            return "Low"

        return "Informational"

    def _calculate_group_status(self, status, window_count):

        if status == "DETECTED":

            if window_count >= 3:
                return "VERY DENGEROUS"

            if window_count == 2:
                return "DANGEROUS"

            return "ATTACK"

        return status

    def _start_group(self, src_ip, result):

        status = result.get("status")

        self.states[src_ip] = {
            "status": status,
            "window_count": 1,
            "request_count": result.get("request_count", 0),
            "last_window_end": result.get("window_end"),
            "attack": result.get("attack")
        }

    def _finish_group(self, src_ip):

        state = self.states.get(src_ip)

        if state is None:
            return None

        status = state["status"]
        window_count = state["window_count"]

        group_status = self._calculate_group_status(
            status,
            window_count
        )

        severity = self._calculate_severity(
            status,
            window_count
        )

        detected = group_status in {
            "ATTACK",
            "DANGEROUS",
            "VERY DENGEROUS"
        }

        alert = group_status != "NORMAL"

        result = {
            "source_ip": src_ip,
            "status": group_status,
            "window_count": window_count,
            "request_count": state["request_count"],
            "attack": state["attack"],
            "severity": severity,
            "detected": detected,
            "alert": alert
        }

        del self.states[src_ip]

        return result

    def process(self, result):

        if result is None:
            return None

        src_ip = result.get("src_ip")

        if not src_ip:
            return None

        current_status = result.get("status")
        current_start = result.get("window_start")
        current_end = result.get("window_end")

        if src_ip not in self.states:

            self._start_group(
                src_ip,
                result
            )

            return None

        state = self.states[src_ip]

        previous_status = state["status"]
        previous_end = state["last_window_end"]

        continuous = True

        if (
            current_start is not None
            and previous_end is not None
        ):

            gap = current_start - previous_end

            if gap > self.allowed_gap:
                continuous = False

        if (
            current_status == previous_status
            and continuous
        ):

            state["window_count"] += 1
            state["request_count"] += result.get("request_count", 0)

            state["last_window_end"] = current_end

            if result.get("attack") is not None:
                state["attack"] = result.get("attack")

            return None

        previous_group = self._finish_group(src_ip)

        self._start_group(
            src_ip,
            result
        )

        return previous_group

    def flush(self):

        results = []

        for src_ip in list(self.states.keys()):

            result = self._finish_group(src_ip)

            if result is not None:
                results.append(result)

        return results