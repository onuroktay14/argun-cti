"""
ARGUN CTI — Fediverse Social Signal Collector
Consumes FediSecFeeds JSON and optionally queries Mastodon instances.
"""

import requests
import logging
import re

logger = logging.getLogger("argun-cti.fedi")

FEDI_FEED_URL = "https://raw.githubusercontent.com/fedisecfeeds/fedisecfeeds.github.io/main/fedi_cve_feed.json"

# Mastodon instances to search
MASTODON_INSTANCES = [
    "https://infosec.exchange",
    "https://ioc.exchange",
]


class FediCollector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ARGUN-CTI/2.0"})

    def collect(self):
        """
        Primary: consume FediSecFeeds JSON (already aggregated).
        This gives us CVSS, EPSS, post count, repo count, nuclei info.
        """
        cve_social = {}

        # ─── FediSecFeeds JSON ───
        try:
            resp = self.session.get(FEDI_FEED_URL, timeout=30)
            resp.raise_for_status()
            feed_data = resp.json()

            for item in feed_data:
                cve_id = item.get("cve_id", "")
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue

                cve_social[cve_id] = {
                    "posts": item.get("post_count", 0),
                    "repos": item.get("repo_count", 0),
                    "nuclei": item.get("nuclei_url", None),
                    "cvss": item.get("cvss_base_score", None),
                    "epss": item.get("epss_score", 0),
                    "description": item.get("description", ""),
                    "updated": item.get("updated_at", None),
                }

            logger.info(f"  FediSecFeeds: {len(cve_social)} CVEs loaded")

        except Exception as e:
            logger.warning(f"FediSecFeeds fetch failed: {e}")
            logger.info("  Falling back to direct Mastodon search...")
            cve_social = self._search_mastodon_direct()

        return cve_social

    def _search_mastodon_direct(self):
        """Fallback: search Mastodon instances directly for CVE mentions."""
        cve_mentions = {}

        for instance in MASTODON_INSTANCES:
            try:
                search_url = f"{instance}/api/v2/search"
                # Search for recent CVE mentions
                resp = self.session.get(
                    search_url,
                    params={"q": "CVE-", "type": "statuses", "limit": 40},
                    timeout=15,
                )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                statuses = data.get("statuses", [])

                for status in statuses:
                    content = status.get("content", "")
                    # Extract CVE IDs from post content
                    found_cves = re.findall(r"CVE-\d{4}-\d{4,7}", content)
                    for cve_id in found_cves:
                        if cve_id not in cve_mentions:
                            cve_mentions[cve_id] = {
                                "posts": 0,
                                "repos": 0,
                                "nuclei": None,
                                "cvss": None,
                                "epss": 0,
                                "description": "",
                                "updated": status.get("created_at"),
                            }
                        cve_mentions[cve_id]["posts"] += 1

            except Exception as e:
                logger.warning(f"Mastodon search failed for {instance}: {e}")

        return cve_mentions
