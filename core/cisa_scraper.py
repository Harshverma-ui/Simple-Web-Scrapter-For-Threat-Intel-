import requests
from bs4 import BeautifulSoup


class CISAScraper:

    BASE_URL = "https://www.cisa.gov"

    ADVISORIES_URL = (
        "https://www.cisa.gov/news-events/"
        "cybersecurity-advisories"
    )

    def __init__(self):

        self.headers = {
            "User-Agent":
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64)"
        }

    # -------------------------
    # Download Page
    # -------------------------

    def fetch_page(self, url):

        try:

            response = requests.get(
                url,
                headers=self.headers,
                timeout=15
            )

            response.raise_for_status()

            return response.text

        except Exception as e:

            print(
                f"[CISA ERROR] "
                f"Failed to fetch {url}"
            )

            print(e)

            return None

    # -------------------------
    # Get Advisory Links
    # -------------------------

    def get_advisory_links(self, limit=20):

        html = self.fetch_page(
            self.ADVISORIES_URL
        )

        if not html:
            return []

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

        links = []

        for a in soup.find_all("a", href=True):

            href = a["href"]

            if "/news-events/" not in href:
                continue

            if "cybersecurity" not in href.lower():
                continue

            if href.startswith("/"):
                href = self.BASE_URL + href

            if href not in links:
                links.append(href)

        return links[:limit]

    # -------------------------
    # Download Advisory
    # -------------------------

    def get_advisory_content(self, url):

        html = self.fetch_page(url)

        if not html:
            return ""

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

        return soup.get_text(
            separator=" ",
            strip=True
        )

    # -------------------------
    # Collect Advisories
    # -------------------------

    def collect_advisories(
        self,
        limit=10
    ):

        advisories = []

        links = self.get_advisory_links(
            limit
        )

        print(
            f"[+] Found "
            f"{len(links)} advisory links"
        )

        for link in links:

            text = self.get_advisory_content(
                link
            )

            if len(text) < 100:
                continue

            advisories.append({

                "url": link,

                "content": text

            })

        return advisories