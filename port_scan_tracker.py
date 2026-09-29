from typing import Any, Dict, List


class PortScanTracker:
    def __init__(self, window_seconds: float = 10.0):
        self.window_seconds = window_seconds

    def track(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        windows = []

        if not packets:
            return windows

        window_start = packets[0]["timestamp"]
        window_packets = []
        window_number = 1

        for packet in packets:
            timestamp = packet["timestamp"]

            if timestamp - window_start < self.window_seconds:
                window_packets.append(packet)
            else:
                result = self._process_window(
                    window_number,
                    window_start,
                    window_packets,
                )

                if result:
                    windows.append(result)

                window_number += 1
                window_start = timestamp
                window_packets = [packet]

        if window_packets:
            result = self._process_window(
                window_number,
                window_start,
                window_packets,
            )

            if result:
                windows.append(result)

        return windows

    def _process_window(
        self,
        window_number: int,
        window_start: float,
        packets: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        sources = {}

        for packet in packets:

            if packet.get("protocol") != "TCP":
                continue

            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            dst_port = packet.get("dst_port")
            flags = str(packet.get("flags", ""))

            if src_ip is None or dst_ip is None:
                continue

            if src_ip not in sources:
                sources[src_ip] = {
                    "destination_ips": set(),
                    "destination_ports": set(),
                    "total_connections": 0,
                    "syn_count": 0,
                    "syn_ack_count": 0,
                    "ack_count": 0,
                    "rst_count": 0,
                }

            data = sources[src_ip]

            data["destination_ips"].add(dst_ip)

            if dst_port is not None:
                data["destination_ports"].add(
                    (dst_ip, dst_port)
                )

            data["total_connections"] += 1

            if "S" in flags and "A" not in flags:
                data["syn_count"] += 1

            if "S" in flags and "A" in flags:
                data["syn_ack_count"] += 1

            if "A" in flags and "S" not in flags:
                data["ack_count"] += 1

            if "R" in flags:
                data["rst_count"] += 1

        results = []

        for source_ip, data in sources.items():

            syn_ack_received = 0

            for packet in packets:

                if packet.get("protocol") != "TCP":
                    continue

                if packet.get("dst_ip") != source_ip:
                    continue

                flags = str(packet.get("flags", ""))

                if "S" in flags and "A" in flags:
                    syn_ack_received += 1

            results.append(
                {
                    "source_ip": source_ip,
                    "destination_ips": list(
                        data["destination_ips"]
                    ),
                    "total_connections": data["total_connections"],
                    "unique_dst_ports": len(
                        data["destination_ports"]
                    ),
                    "syn_count": data["syn_count"],
                    "syn_ack_count": (
                        data["syn_ack_count"]
                        + syn_ack_received
                    ),
                    "ack_count": data["ack_count"],
                    "rst_count": data["rst_count"],
                }
            )

        window_end = packets[-1]["timestamp"]

        return {
            "window": window_number,
            "window_start": window_start,
            "window_end": window_end,
            "duration": window_end - window_start,
            "sources": results,
        }