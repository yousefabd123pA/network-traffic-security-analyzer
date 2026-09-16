from datetime import datetime
import os


class LogManager:

    def __init__(self, log_file="security_analyzer.log"):

        self.log_file = os.path.join(
            os.path.dirname(
                os.path.abspath(__file__)
            ),
            log_file
        )

    def _write(self, level, message):

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        log_entry = (
            f"[{timestamp}] "
            f"[{level}] "
            f"{message}\n"
        )

        with open(
            self.log_file,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(log_entry)

    def info(self, message):

        self._write(
            "INFO",
            message
        )

    def detection(self, message):

        self._write(
            "DETECTION",
            message
        )

    def alert(self, message):

        self._write(
            "ALERT",
            message
        )

    def confirmed(self, message):

        self._write(
            "CONFIRMED",
            message
        )

    def report(self, message):

        self._write(
            "REPORT",
            message
        )

    def error(self, message):

        self._write(
            "ERROR",
            message
        )

    def get_log_file(self):

        return self.log_file
