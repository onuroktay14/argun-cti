"""
ARGUN CTI — CISA Known Exploited Vulnerabilities Collector
"""

import requests
import logging

logger = logging.getLogger("argun-cti.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVCollector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ARGUN-CTI/2.0"})

    def collect(self):
        """Returns dict of CVE-ID → KEV metadata."""
        kev_data = {}
        try:
            resp = self.session.get(KEV_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID", "")
                if cve_id:
                    kev_data[cve_id] = {
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "vulnerability_name": vuln.get("vulnerabilityName", ""),
                        "date_added": vuln.get("dateAdded", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                        "required_action": vuln.get("requiredAction", ""),
                    }
        except Exception as e:
            logger.error(f"KEV fetch error: {e}")

        return kev_data
