import re


class ThreatParser:

    # -------------------------
    # Regex Patterns
    # -------------------------

    CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"

    IP_PATTERN = (
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    URL_PATTERN = (
        r"https?://[^\s<>\"']+"
    )

    DOMAIN_PATTERN = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"[a-zA-Z]{2,}\b"
    )

    SHA256_PATTERN = (
        r"\b[a-fA-F0-9]{64}\b"
    )

    # -------------------------
    # Extract CVEs
    # -------------------------

    def extract_cves(self, text):

        return list(
            set(
                re.findall(
                    self.CVE_PATTERN,
                    text,
                    flags=re.IGNORECASE
                )
            )
        )

    # -------------------------
    # Extract IPs
    # -------------------------

    def extract_ips(self, text):

        return list(
            set(
                re.findall(
                    self.IP_PATTERN,
                    text
                )
            )
        )

    # -------------------------
    # Extract URLs
    # -------------------------

    def extract_urls(self, text):

        return list(
            set(
                re.findall(
                    self.URL_PATTERN,
                    text
                )
            )
        )

    # -------------------------
    # Extract Domains
    # -------------------------

    def extract_domains(self, text):

        domains = re.findall(
            self.DOMAIN_PATTERN,
            text
        )

        clean_domains = []

        for domain in domains:

            domain = domain.lower()

            if domain.startswith(
                ("www.",)
            ):
                domain = domain[4:]

            clean_domains.append(
                domain
            )

        return list(
            set(clean_domains)
        )

    # -------------------------
    # Extract SHA256
    # -------------------------

    def extract_hashes(self, text):

        return list(
            set(
                re.findall(
                    self.SHA256_PATTERN,
                    text
                )
            )
        )

    # -------------------------
    # Extract All IOCs
    # -------------------------

    def extract_iocs(self, text):

        return {

            "ips":
                self.extract_ips(text),

            "urls":
                self.extract_urls(text),

            "domains":
                self.extract_domains(text),

            "hashes":
                self.extract_hashes(text)
        }

    # -------------------------
    # Parse Advisory
    # -------------------------

    def parse_advisory(self, text):

        return {

            "cves":
                self.extract_cves(text),

            "iocs":
                self.extract_iocs(text)
        }