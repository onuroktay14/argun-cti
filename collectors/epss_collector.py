"""
ARGUN CTI — EPSS (Exploit Prediction Scoring System) Collector
Fetches EPSS scores from FIRST.org API.
"""

import requests
import logging

logger = logging.getLogger("argun-cti.epss")

EPSS_API_BASE = "https://api.first.org/data/v1/epss"


class EPSSCollector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ARGUN-CTI/2.0"})

    def collect(self, cve_ids):
        """Fetch EPSS scores for a list of CVE IDs. Batches of 100."""
        all_scores = {}

        # Process in batches of 100
        for i in range(0, len(cve_ids), 100):
            batch = cve_ids[i:i + 100]
            cve_param = ",".join(batch)

            try:
                resp = self.session.get(
                    EPSS_API_BASE,
                    params={"cve": cve_param},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()

                for item in data.get("data", []):
                    cve_id = item.get("cve", "")
                    if cve_id:
                        all_scores[cve_id] = {
                            "epss": float(item.get("epss", 0)),
                            "percentile": float(item.get("percentile", 0)),
                        }
            except Exception as e:
                logger.error(f"EPSS batch error (index {i}): {e}")

        return all_scores
