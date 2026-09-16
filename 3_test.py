from tracker import HTTPRequestTracker


tracker = HTTPRequestTracker(window_seconds=10)

packets = [
    {"src_ip": "10.0.0.50", "timestamp": 0.00},
    {"src_ip": "10.0.0.50", "timestamp": 0.10},
    {"src_ip": "10.0.0.50", "timestamp": 0.20},
    {"src_ip": "10.0.0.50", "timestamp": 0.30},
    {"src_ip": "10.0.0.50", "timestamp": 5.00},
]


for packet in packets:

    result = tracker.update(packet)

    print("\n" + "=" * 40)
    print(f"Source IP          : {result['src_ip']}")
    print(f"Request Count      : {result['request_count']}")
    print(f"Request Rate       : {result['request_rate']:.2f} req/s")
    print(f"Avg Inter-Arrival  : {result['avg_inter_arrival']:.4f} sec")
    print(f"Sustained Duration : {result['sustained_duration']:.2f} sec")
    print("=" * 40)