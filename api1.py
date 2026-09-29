from flask import Flask, request, jsonify, send_from_directory

import os

from parser import parse_pcap

from tracker import HTTPRequestTracker
from http_flood import HTTPFloodRule
from engine import DetectionEngine

from port_scan_tracker import PortScanTracker
from port_scan_rule import PortScanRule
from port_scan_engine import PortScanEngine

from alert_manager import AlertManager
from log_manager import LogManager
from report_generator import ReportGenerator


app = Flask(__name__)

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

GUI_FILE = os.path.join(
    BASE_DIR,
    "GUI.html"
)


# =========================================================
# PCAP ANALYSIS
# =========================================================

def analyze_pcap_file(pcap_file):

    # =====================================================
    # HTTP FLOOD
    # =====================================================

    tracker = HTTPRequestTracker(
        window_seconds=10
    )

    rule = HTTPFloodRule(
        min_requests=100,
        min_rate=40,
        max_inter_arrival=0.05
    )

    engine = DetectionEngine(
        allowed_gap=10
    )

    alert_manager = AlertManager()
    log_manager = LogManager()
    report_generator = ReportGenerator()

    final_reports = []

    pending_reports = []

    # =====================================================
    # PORT SCAN
    # =====================================================

    port_scan_tracker = PortScanTracker(
        window_seconds=10
    )

    port_scan_rule = PortScanRule()

    port_scan_engine = PortScanEngine(
        port_scan_rule
    )

    # =====================================================
    # PARSE PCAP
    # =====================================================

    packets = parse_pcap(
        pcap_file
    )

    # =====================================================
    # HTTP FLOOD ANALYSIS
    # =====================================================

    for packet in packets:

        if packet.get("http_method") is None:
            continue

        tracker_result = tracker.update(
            packet
        )

        if tracker_result is None:
            continue

        rule_result = rule.detect(
            tracker_result
        )

        result = {
            **tracker_result,
            **rule_result
        }

        engine_result = engine.process(
            result
        )

        if engine_result is None:
            continue

        alert = alert_manager.create_alert(
            engine_result
        )

        if alert is None:
            continue

        log_manager.alert(
            f"{alert['attack']} | "
            f"Source: {alert['source_ip']} | "
            f"Status: {alert['status']} | "
            f"Severity: {alert['severity']}"
        )

        pending_reports.append(
            (
                alert,
                engine_result
            )
        )

    # =====================================================
    # FLUSH HTTP TRACKER
    # =====================================================

    tracker_results = tracker.flush()

    for tracker_result in tracker_results:

        rule_result = rule.detect(
            tracker_result
        )

        result = {
            **tracker_result,
            **rule_result
        }

        engine_result = engine.process(
            result
        )

        if engine_result is None:
            continue

        alert = alert_manager.create_alert(
            engine_result
        )

        if alert is None:
            continue

        log_manager.alert(
            f"{alert['attack']} | "
            f"Source: {alert['source_ip']} | "
            f"Status: {alert['status']} | "
            f"Severity: {alert['severity']}"
        )

        pending_reports.append(
            (
                alert,
                engine_result
            )
        )

    # =====================================================
    # FLUSH HTTP ENGINE
    # =====================================================

    engine_results = engine.flush()

    for engine_result in engine_results:

        alert = alert_manager.create_alert(
            engine_result
        )

        if alert is None:
            continue

        log_manager.alert(
            f"{alert['attack']} | "
            f"Source: {alert['source_ip']} | "
            f"Status: {alert['status']} | "
            f"Severity: {alert['severity']}"
        )

        pending_reports.append(
            (
                alert,
                engine_result
            )
        )

    # =====================================================
    # HTTP SUSTAINED DURATION
    # =====================================================

    sustained_durations = (
        tracker.get_sustained_durations()
    )

    # =====================================================
    # HTTP FINAL REPORTS
    # =====================================================

    for alert, engine_result in pending_reports:

        source_ip = engine_result.get(
            "source_ip",
            alert.get("source_ip")
        )

        duration = sustained_durations.get(
            source_ip,
            0.0
        )

        tracker_data = {
            "sustained_duration": duration
        }

        report = report_generator.generate(
            alert,
            engine_result,
            tracker_data
        )

        if report is not None:
            final_reports.append(
                report
            )

    # =====================================================
    # PORT SCAN ANALYSIS
    # =====================================================

    port_scan_windows = port_scan_tracker.track(
        packets
    )

    port_scan_results = port_scan_engine.process(
        port_scan_windows
    )

    return final_reports, port_scan_results


# =========================================================
# GUI
# =========================================================

@app.route("/")
def index():

    return send_from_directory(
        BASE_DIR,
        "GUI.html"
    )


# =========================================================
# API
# =========================================================

@app.route(
    "/api/analyze",
    methods=["POST"]
)
def analyze():

    # -----------------------------------------------------
    # Check uploaded file
    # -----------------------------------------------------

    if "file" not in request.files:

        return jsonify({
            "success": False,
            "error": "No PCAP file uploaded."
        }), 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":

        return jsonify({
            "success": False,
            "error": "No file selected."
        }), 400

    filename = uploaded_file.filename.lower()

    if not filename.endswith(
        (".pcap", ".pcapng")
    ):

        return jsonify({
            "success": False,
            "error": (
                "Only PCAP and PCAPNG files "
                "are supported."
            )
        }), 400

    # -----------------------------------------------------
    # Save uploaded PCAP
    # -----------------------------------------------------

    upload_dir = os.path.join(
        BASE_DIR,
        "uploads"
    )

    os.makedirs(
        upload_dir,
        exist_ok=True
    )

    pcap_path = os.path.join(
        upload_dir,
        uploaded_file.filename
    )

    uploaded_file.save(
        pcap_path
    )

    # -----------------------------------------------------
    # Analyze PCAP
    # -----------------------------------------------------

    try:

        reports, port_scan_results = (
            analyze_pcap_file(
                pcap_path
            )
        )

        # -------------------------------------------------
        # No HTTP report and no Port Scan
        # -------------------------------------------------

        if not reports and not port_scan_results:

            return jsonify({
                "success": True,
                "message": (
                    "No security incident was detected."
                ),
                "report": None,
                "port_scan": []
            })

        response = {
            "success": True,
            "report": None,
            "port_scan": port_scan_results
        }

        # -------------------------------------------------
        # HTTP Report
        # -------------------------------------------------

        if reports:

            report = reports[-1]

            response.update({
                "source_ip":
                    report["source_ip"],

                "attack":
                    report["attack"],

                "status":
                    report["status"],

                "severity":
                    report["severity"],

                "request_count":
                    report["request_count"],

                "sustained_duration":
                    report["sustained_duration"],

                "report":
                    report["narrative"],

                "alert_id":
                    report["alert_id"]
            })

        return jsonify(response)

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )