class PortScanReportGenerator:

    def generate(self, data):

        scan_type = data["scan_type"]

        if scan_type == "SYN Scan":
            analysis = (
                "The source IP generated multiple SYN packets toward "
                "different destination ports, consistent with SYN scanning activity."
            )

        elif scan_type == "Connect Scan":
            analysis = (
                "The source IP made multiple TCP connection attempts toward "
                "different destination ports, consistent with Connect scanning activity."
            )

        elif scan_type == "ACK Scan":
            analysis = (
                "The source IP generated multiple ACK packets toward "
                "different destination ports, consistent with ACK scanning activity."
            )

        else:
            analysis = (
                "The source IP generated traffic toward multiple destination "
                "ports, consistent with port scanning activity."
            )

        return (
           

            "Incident Summary:\n "
            f"A {scan_type} was detected during network traffic analysis. "
            f"Source: {data['source_ip']} → "
            f"Target: {data['destination_ips'][0]}.\n\n"

            "Detection Details: "
            f"Attack: {data['attack']} | "
            f"Scan Type: {scan_type} | "
            f"Window: {data['window']}.\n\n"

            "SOC Analysis: "
            f"{analysis}\n\n"

            "Assessment: "
            "Verify whether the source IP is authorized to perform "
            "network scanning."
        )