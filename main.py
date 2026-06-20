import sys

from PyQt6.QtWidgets import QApplication

from gui.main_window import MainWindow

from core.database import Database

from worker.worker_thread import FeedWorker


class ThreatIntelApp:

    def __init__(self):

        self.db = Database()

        self.window = MainWindow()

        self.worker = None

        self.setup_signals()

        self.load_database()

    # ----------------------
    # SIGNALS
    # ----------------------

    def setup_signals(self):

        self.window.refresh_btn.clicked.connect(
            self.start_worker
        )

        self.window.search_box.textChanged.connect(
            self.search_cve
        )

        self.window.severity_filter.currentTextChanged.connect(
            self.filter_severity
        )

    # ----------------------
    # START THREAD
    # ----------------------

    def start_worker(self):

        self.window.refresh_btn.setEnabled(
            False
        )

        self.window.refresh_btn.setText(
            "Updating..."
        )

        self.worker = FeedWorker()

        self.worker.finished.connect(
            self.worker_finished
        )

        self.worker.status.connect(
            self.show_status
        )

        self.worker.start()

    # ----------------------
    # THREAD COMPLETE
    # ----------------------

    def worker_finished(self):

        self.load_database()

        self.window.refresh_btn.setEnabled(
            True
        )

        self.window.refresh_btn.setText(
            "Refresh Threat Feed"
        )

        print(
            "[+] Feed Updated"
        )

    # ----------------------
    # STATUS
    # ----------------------

    def show_status(self, message):

        self.window.status_label.setText(
            message
        )

        print(
            f"[WORKER] {message}"
        )

    # ----------------------
    # LOAD DATABASE
    # ----------------------

    def load_database(self):

        threats = self.db.get_all_threats()

        iocs = self.db.get_all_iocs()

        stats = self.db.get_statistics()

        self.window.load_threats(
            threats
        )

        self.window.load_iocs(
            iocs
        )

        self.window.update_stats(
            stats
        )

    # ----------------------
    # SEARCH
    # ----------------------

    def search_cve(self):

        text = self.window.search_box.text()

        if not text:

            self.load_database()

            return

        threats = self.db.search_cve(
            text
        )

        self.window.load_threats(
            threats
        )

    # ----------------------
    # FILTER
    # ----------------------

    def filter_severity(self):

        severity = (
            self.window.severity_filter.currentText()
        )

        if severity == "All":

            self.load_database()

            return

        threats = self.db.filter_severity(
            severity
        )

        self.window.load_threats(
            threats
        )

    # ----------------------
    # RUN
    # ----------------------

    def run(self):

        self.window.show()


if __name__ == "__main__":

    app = QApplication(sys.argv)

    dashboard = ThreatIntelApp()

    dashboard.run()

    sys.exit(
        app.exec()
    )