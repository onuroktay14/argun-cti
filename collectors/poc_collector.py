"""
ARGUN CTI — PoC & Exploit Intelligence Collector
Checks GitHub for PoC repos and Nuclei templates.
"""

import requests
import logging
import time

logger = logging.getLogger("argun-cti.poc")

GITHUB_API = "https://api.github.com"
NUCLEI_TEMPLATES_API = "https://api.github.com/search/code"


class PoCCollector:
    def __init__(self, github_token=None):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ARGUN-CTI/2.0"})
        if github_token:
            self.session.headers["Authorization"] = f"token {github_token}"
        import os
        token = github_token or os.environ.get("GITHUB_TOKEN")
        if token:
            self.session.headers["Authorization"] = f"token {token}"

    def collect(self, cve_ids):
        """Check for PoC repos and Nuclei templates for given CVEs."""
        poc_data = {}

        # Only check CVEs that are likely to have PoCs
        # (recent or high-profile — limit API calls)
        check_limit = min(len(cve_ids), 150)
        checked = 0

        for cve_id in cve_ids[:check_limit]:
            if checked >= check_limit:
                break

            try:
                result = self._check_github_poc(cve_id)
                if result["has_poc"] or result.get("nuclei_template"):
                    poc_data[cve_id] = result
                checked += 1

                # Rate limit: 10 req/min for unauthenticated
                time.sleep(2)

            except Exception as e:
                logger.debug(f"PoC check failed for {cve_id}: {e}")
                continue

        return poc_data

    def _check_github_poc(self, cve_id):
        """Search GitHub for PoC repositories matching a CVE ID."""
        result = {
            "has_poc": False,
            "poc_urls": [],
            "nuclei_template": None,
            "repo_count": 0,
        }

        try:
            # Search repositories
            resp = self.session.get(
                f"{GITHUB_API}/search/repositories",
                params={"q": cve_id, "sort": "stars", "per_page": 5},
                timeout=15,
            )

            if resp.status_code == 200:
                data = resp.json()
                repos = data.get("items", [])
                result["repo_count"] = data.get("total_count", 0)

                for repo in repos[:5]:
                    name = repo.get("full_name", "").lower()
                    desc = (repo.get("description") or "").lower()
                    cve_lower = cve_id.lower()

                    # Heuristic: repo name or description contains CVE ID
                    if cve_lower in name or cve_lower in desc:
                        result["has_poc"] = True
                        result["poc_urls"].append({
                            "url": repo.get("html_url", ""),
                            "name": repo.get("full_name", ""),
                            "stars": repo.get("stargazers_count", 0),
                            "description": repo.get("description", ""),
                        })

                        # Check if it's a nuclei template
                        if "nuclei" in name or "nuclei-templates" in name:
                            result["nuclei_template"] = repo.get("html_url", "")

            elif resp.status_code == 403:
                logger.warning("GitHub API rate limit reached")
                raise Exception("Rate limited")

        except Exception as e:
            raise e

        return result
