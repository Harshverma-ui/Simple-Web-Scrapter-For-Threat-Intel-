from PyQt6.QtCore import QThread, pyqtSignal

from core.cisa_scraper import CISAScraper
from core.parser import ThreatParser
from core.nvd_client import NVDClient
from core.database import Database


class FeedWorker(QThread):

    finished = pyqtSignal()
    status = pyqtSignal(str)

    def run(self):

        db = Database()

        scraper = CISAScraper()

        parser = ThreatParser()

        nvd = NVDClient()

        self.status.emit(
            "Downloading CISA advisories..."
        )

        advisories = scraper.collect_advisories(
            limit=10
        )

        self.status.emit(
            f"Found {len(advisories)} advisories"
        )

        for advisory in advisories:

            parsed = parser.parse_advisory(
                advisory["content"]
            )

            cves = parsed["cves"]

            iocs = parsed["iocs"]

            for cve in cves:

                self.status.emit(
                    f"Processing {cve}"
                )

                try:

                    info = nvd.get_cve_details(
                        cve
                    )

                except Exception:

                    info = None

                if info:

                    severity = info["severity"]

                    cvss = info["cvss"]

                    description = info["description"]

                else:

                    severity = "UNKNOWN"

                    cvss = 0.0

                    description = (
                        "NVD unavailable"
                    )

                threat_id = db.insert_threat(
                    cve,
                    severity,
                    cvss,
                    description
                )

                if not threat_id:
                    continue

                for ip in iocs["ips"]:

                    db.insert_ioc(
                        threat_id,
                        "IP",
                        ip
                    )

                for url in iocs["urls"]:

                    db.insert_ioc(
                        threat_id,
                        "URL",
                        url
                    )

                for domain in iocs["domains"]:

                    db.insert_ioc(
                        threat_id,
                        "DOMAIN",
                        domain
                    )

                for h in iocs["hashes"]:

                    db.insert_ioc(
                        threat_id,
                        "SHA256",
                        h
                    )

        self.status.emit(
            "Feed update completed"
        )

        db.close()

        self.finished.emit()