from port_scan_report_generator import PortScanReportGenerator


class PortScanEngine:

    def __init__(self, rule):
        self.rule = rule
        self.report_generator = PortScanReportGenerator()

    def process(self, windows):

        results = []

        for window in windows:

            for source in window["sources"]:

                detection = self.rule.detect(source)

                if detection:

                    result = {
                        "source_ip": source["source_ip"],
                        "destination_ips": source["destination_ips"],
                        "window": window["window"],
                        "window_start": window["window_start"],
                        "window_end": window["window_end"],
                        "attack": detection["attack"],
                        "scan_type": detection["scan_type"],
                    }

                    result["report"] = self.report_generator.generate(result)

                    results.append(result)

        return results