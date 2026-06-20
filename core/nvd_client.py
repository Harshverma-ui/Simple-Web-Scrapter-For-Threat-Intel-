import requests
import time


class NVDClient:

    BASE_URL = (
        "https://services.nvd.nist.gov/"
        "rest/json/cves/2.0"
    )

    def __init__(self, api_key=None):

        self.api_key = api_key

        self.headers = {
            "User-Agent": (
                "ThreatIntelDashboard/1.0"
            )
        }

        if api_key:
            self.headers["apiKey"] = api_key

    # -------------------------
    # Query NVD
    # -------------------------

    def get_cve_details(self, cve_id):

        try:

            response = requests.get(
                self.BASE_URL,
                params={
                    "cveId": cve_id
                },
                headers=self.headers,
                timeout=20
            )

            response.raise_for_status()

            data = response.json()

            vulnerabilities = data.get(
                "vulnerabilities",
                []
            )

            if not vulnerabilities:
                return None

            vuln = vulnerabilities[0]

            cve_data = vuln.get(
                "cve",
                {}
            )

            description = self.extract_description(
                cve_data
            )

            cvss_score, severity = (
                self.extract_cvss(
                    cve_data
                )
            )

            return {

                "cve": cve_id,

                "description":
                    description,

                "cvss":
                    cvss_score,

                "severity":
                    severity
            }

        except Exception as e:

            print(
                f"[NVD ERROR] "
                f"{cve_id}: {e}"
            )

            return None

    # -------------------------
    # Extract Description
    # -------------------------

    def extract_description(
        self,
        cve_data
    ):

        descriptions = cve_data.get(
            "descriptions",
            []
        )

        for item in descriptions:

            if (
                item.get("lang")
                == "en"
            ):

                return item.get(
                    "value",
                    ""
                )

        return ""

    # -------------------------
    # Extract CVSS
    # -------------------------

    def extract_cvss(
        self,
        cve_data
    ):

        metrics = cve_data.get(
            "metrics",
            {}
        )

        #
        # CVSS v4
        #
        if "cvssMetricV40" in metrics:

            metric = (
                metrics[
                    "cvssMetricV40"
                ][0]
            )

            return (

                metric[
                    "cvssData"
                ][
                    "baseScore"
                ],

                metric[
                    "cvssData"
                ][
                    "baseSeverity"
                ]
            )

        #
        # CVSS v3.1
        #
        if "cvssMetricV31" in metrics:

            metric = (
                metrics[
                    "cvssMetricV31"
                ][0]
            )

            return (

                metric[
                    "cvssData"
                ][
                    "baseScore"
                ],

                metric[
                    "cvssData"
                ][
                    "baseSeverity"
                ]
            )

        #
        # CVSS v3.0
        #
        if "cvssMetricV30" in metrics:

            metric = (
                metrics[
                    "cvssMetricV30"
                ][0]
            )

            return (

                metric[
                    "cvssData"
                ][
                    "baseScore"
                ],

                metric[
                    "cvssData"
                ][
                    "baseSeverity"
                ]
            )

        return (
            0.0,
            "UNKNOWN"
        )

    # -------------------------
    # Bulk Enrichment
    # -------------------------

    def enrich_cves(
        self,
        cve_list
    ):

        results = []

        for cve in cve_list:

            info = (
                self.get_cve_details(
                    cve
                )
            )

            if info:
                results.append(
                    info
                )

            #
            # NVD rate limit
            #
            time.sleep(0.6)

        return results