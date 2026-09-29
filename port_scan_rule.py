class PortScanRule:

    def __init__(
        self,
        min_unique_ports: int = 20,
        min_ack_packets: int = 20,
    ):
        self.min_unique_ports = min_unique_ports
        self.min_ack_packets = min_ack_packets

    def detect(self, data):

        unique_ports = data["unique_dst_ports"]
        syn_count = data["syn_count"]
        syn_ack_count = data["syn_ack_count"]
        ack_count = data["ack_count"]

        # SYN Scan
        if (
            unique_ports >= self.min_unique_ports
            and syn_count > 0
            and ack_count == 0
        ):
            return {
                "attack": "Port Scan",
                "scan_type": "SYN Scan",
            }

        # Connect Scan
        if (
            unique_ports >= self.min_unique_ports
            and syn_count > 0
            and syn_ack_count > 0
            and ack_count > 0
        ):
            return {
                "attack": "Port Scan",
                "scan_type": "Connect Scan",
            }

        # ACK Scan
        if (
            ack_count >= self.min_ack_packets
            and syn_count == 0
            and syn_ack_count == 0
        ):
            return {
                "attack": "Port Scan",
                "scan_type": "ACK Scan",
            }

        return None