from scapy.all import rdpcap, IP, TCP, UDP, ICMP


def detect_application(protocol, src_port, dst_port):
    ports = {src_port, dst_port}

    if protocol == "TCP":
        if 80 in ports:
            return "HTTP"

        if 443 in ports:
            return "HTTPS/TLS"

        if 53 in ports:
            return "DNS"

        return "TCP/Unknown"

    if protocol == "UDP":
        if 53 in ports:
            return "DNS"

        if 443 in ports:
            return "QUIC"

        return "UDP/Unknown"

    if protocol == "ICMP":
        return "ICMP"

    return "Unknown"


def detect_http_request(packet):
    """Detect HTTP request methods from TCP payload."""

    if not packet.haslayer(TCP):
        return None

    tcp = packet[TCP]

    if len(tcp.payload) == 0:
        return None

    try:
        payload = bytes(tcp.payload).decode(
            "utf-8",
            errors="ignore"
        )
    except Exception:
        return None

    methods = [
        "GET ",
        "POST ",
        "PUT ",
        "DELETE ",
        "HEAD ",
        "OPTIONS ",
        "PATCH "
    ]

    for method in methods:
        if payload.startswith(method):
            return method.strip()

    return None


def parse_packet(packet):
    data = {
        "timestamp": float(packet.time),
        "src_ip": None,
        "dst_ip": None,
        "protocol": "Unknown",
        "application": "Unknown",
        "src_port": None,
        "dst_port": None,
        "flags": None,
        "seq": None,
        "ack": None,
        "length": len(packet),
        "payload_length": 0,
        "http_method": None
    }

    # IP Layer
    if packet.haslayer(IP):
        ip = packet[IP]

        data["src_ip"] = ip.src
        data["dst_ip"] = ip.dst

    # TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]

        data["protocol"] = "TCP"
        data["src_port"] = tcp.sport
        data["dst_port"] = tcp.dport
        data["flags"] = str(tcp.flags)
        data["seq"] = tcp.seq
        data["ack"] = tcp.ack
        data["payload_length"] = len(tcp.payload)

    # UDP
    elif packet.haslayer(UDP):
        udp = packet[UDP]

        data["protocol"] = "UDP"
        data["src_port"] = udp.sport
        data["dst_port"] = udp.dport
        data["payload_length"] = len(udp.payload)

    # ICMP
    elif packet.haslayer(ICMP):
        data["protocol"] = "ICMP"
        data["payload_length"] = len(
            packet[ICMP].payload
        )

    # Application Protocol
    data["application"] = detect_application(
        data["protocol"],
        data["src_port"],
        data["dst_port"]
    )

    # HTTP Request Detection
    http_method = detect_http_request(packet)

    if http_method is not None:
        data["application"] = "HTTP"
        data["http_method"] = http_method

    return data


def parse_pcap(filename):
    packets = rdpcap(filename)

    parsed_packets = []

    for packet in packets:
        parsed_packet = parse_packet(packet)
        parsed_packets.append(parsed_packet)

    return parsed_packets


def main():
    filename = "http_flood_test.pcap"

    packets = parse_pcap(filename)

    print(f"Total packets: {len(packets)}")
    print("=" * 75)

    for number, packet in enumerate(packets, start=1):
        print(f"Packet #{number}")

        print(f"Timestamp:       {packet['timestamp']} s")
        print(f"Source IP:       {packet['src_ip']}")
        print(f"Dest IP:         {packet['dst_ip']}")
        print(f"Protocol:        {packet['protocol']}")
        print(f"Application:     {packet['application']}")
        print(f"HTTP Method:     {packet['http_method']}")
        print(f"Src Port:        {packet['src_port']}")
        print(f"Dst Port:        {packet['dst_port']}")
        print(f"Flags:           {packet['flags']}")
        print(f"Seq:             {packet['seq']}")
        print(f"Ack:             {packet['ack']}")
        print(f"Length:          {packet['length']} bytes")
        print(
            f"Payload Length:  "
            f"{packet['payload_length']} bytes"
        )

        print("-" * 75)


if __name__ == "__main__":
    main()