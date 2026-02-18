"""
ARGUN CTI — NVD API 2.0 Collector
Fetches recent CVEs from the National Vulnerability Database.
"""

import requests
import logging
import time
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("argun-cti.nvd")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDCollector:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ARGUN-CTI/2.0"})
        if api_key:
            self.session.headers["apiKey"] = api_key

    def collect(self, hours_back=72):
        """Collect CVEs modified in the last N hours."""
        cves = {}
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours_back)

        params = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 200,
            "startIndex": 0,
        }

        total_results = None
        while True:
            try:
                resp = self.session.get(NVD_API_BASE, params=params, timeout=30)
                if resp.status_code == 403:
                    logger.warning("NVD rate limit hit, waiting 30s...")
                    time.sleep(30)
                    continue
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.error(f"NVD API error: {e}")
                break

            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info(f"  NVD total results: {total_results}")

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                cve_item = item.get("cve", {})
                cve_id = cve_item.get("id", "")
                if not cve_id.startswith("CVE-"):
                    continue

                parsed = self._parse_cve(cve_item)
                if parsed:
                    cves[cve_id] = parsed

            params["startIndex"] += len(vulnerabilities)
            if params["startIndex"] >= total_results:
                break

            # Rate limiting: 6s without key, 0.6s with key
            delay = 0.6 if self.api_key else 6
            time.sleep(delay)

        return cves

    def _parse_cve(self, cve_item):
        """Parse a single CVE item from NVD API response."""
        cve_id = cve_item.get("id", "")

        # Description
        descriptions = cve_item.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS Score
        cvss_score = None
        cvss_vector = None
        cvss_severity = None
        metrics = cve_item.get("metrics", {})

        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                cvss_severity = cvss_data.get("baseSeverity",
                                              metric_list[0].get("baseSeverity"))
                break

        # CWE
        cwes = []
        weaknesses = cve_item.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                cwe_val = desc.get("value", "")
                if cwe_val.startswith("CWE-"):
                    cwes.append(cwe_val)

        # References
        references = []
        for ref in cve_item.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", []),
            })

        # CPE (affected products)
        affected_products = []
        configurations = cve_item.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpe = match.get("criteria", "")
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            affected_products.append({
                                "vendor": parts[3],
                                "product": parts[4],
                                "cpe": cpe,
                            })

        # Dates
        published = cve_item.get("published", "")
        last_modified = cve_item.get("lastModified", "")

        # Days since publish
        days_since = 999
        if published:
            try:
                pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                days_since = (datetime.now(timezone.utc) - pub_dt).days
            except Exception:
                pass

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cvss_severity": cvss_severity,
            "cwes": cwes,
            "affected_products": affected_products,
            "references": references,
            "published": published,
            "last_modified": last_modified,
            "days_since_publish": days_since,
            "source": "nvd",
            "in_kev": False,
            "kev_data": None,
            "epss_score": 0,
            "epss_percentile": 0,
            "social_posts": 0,
            "social_repos": 0,
            "has_poc": False,
            "poc_urls": [],
            "nuclei_template": None,
            "mitre_techniques": [],
        }
