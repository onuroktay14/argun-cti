"""
ARGUN CTI — JSON Output Generator
Generates all data files consumed by the frontend.
"""

import json
import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger("argun-cti.output")


class JSONGenerator:
    def __init__(self, output_dir="data"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_cve_feed(self, cve_database, timestamp):
        """Generate the main CVE feed JSON file."""
        # Sort by ATS score descending
        sorted_cves = sorted(
            cve_database.values(),
            key=lambda x: x.get("ats_score", 0),
            reverse=True,
        )

        output = {
            "meta": {
                "generated_at": timestamp.isoformat(),
                "generator": "ARGUN CTI v2.0",
                "website": "https://cti.argunsec.com",
                "total_cves": len(sorted_cves),
            },
            "cves": sorted_cves,
        }

        path = os.path.join(self.output_dir, "cve_feed.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, default=str)
        logger.info(f"  → Generated {path} ({len(sorted_cves)} CVEs)")

    def generate_ip_blacklist(self, ip_data, timestamp):
        """Generate the IP blacklist JSON file."""
        # Sort by hit_count descending
        sorted_ips = sorted(
            ip_data.values(),
            key=lambda x: x.get("hit_count", 0),
            reverse=True,
        )

        output = {
            "meta": {
                "generated_at": timestamp.isoformat(),
                "generator": "ARGUN CTI v2.0",
                "total_ips": len(sorted_ips),
                "sources": [
                    "stamparm/ipsum", "abuse.ch Feodo", "Blocklist.de",
                    "Emerging Threats", "CINS Army", "Binary Defense",
                    "abuse.ch SSL Blacklist", "URLhaus",
                ],
                "confidence_threshold": "2+ sources",
            },
            "blacklist": sorted_ips,
        }

        path = os.path.join(self.output_dir, "ip_blacklist.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, default=str)
        logger.info(f"  → Generated {path} ({len(sorted_ips)} IPs)")

    def generate_blacklist_txt(self, ip_data):
        """Generate plain text blacklist for firewall import."""
        # Sort by hit_count
        sorted_ips = sorted(
            ip_data.keys(),
            key=lambda ip: ip_data[ip].get("hit_count", 0),
            reverse=True,
        )

        path = os.path.join(self.output_dir, "blacklist.txt")
        with open(path, "w") as f:
            f.write("# ARGUN CTI — IP Blacklist\n")
            f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"# Total IPs: {len(sorted_ips)}\n")
            f.write("# Confidence: 2+ independent sources\n")
            f.write("# https://cti.argunsec.com\n")
            f.write("#\n")
            for ip in sorted_ips:
                f.write(f"{ip}\n")
        logger.info(f"  → Generated {path} ({len(sorted_ips)} IPs)")

    def generate_stats(self, cve_database, ip_data, timestamp):
        """Generate dashboard statistics JSON."""
        # CVE Stats
        total_cves = len(cve_database)
        critical_count = sum(
            1 for c in cve_database.values()
            if c.get("ats_level") == "CRITICAL"
        )
        high_count = sum(
            1 for c in cve_database.values()
            if c.get("ats_level") == "HIGH"
        )
        kev_count = sum(
            1 for c in cve_database.values()
            if c.get("in_kev")
        )
        poc_count = sum(
            1 for c in cve_database.values()
            if c.get("has_poc") or c.get("nuclei_template")
        )

        # Vendor distribution (top 20)
        vendor_counts = {}
        for cve in cve_database.values():
            for prod in cve.get("affected_products", []):
                vendor = prod.get("vendor", "unknown")
                vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
        top_vendors = sorted(
            vendor_counts.items(), key=lambda x: x[1], reverse=True
        )[:20]

        # CWE distribution (top 15)
        cwe_counts = {}
        for cve in cve_database.values():
            for cwe in cve.get("cwes", []):
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        top_cwes = sorted(
            cwe_counts.items(), key=lambda x: x[1], reverse=True
        )[:15]

        # Severity distribution
        severity_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for cve in cve_database.values():
            level = cve.get("ats_level", "INFO")
            severity_dist[level] = severity_dist.get(level, 0) + 1

        # MITRE tactic distribution
        tactic_counts = {}
        for cve in cve_database.values():
            for tech in cve.get("mitre_techniques", []):
                tactic = tech.get("tactic", "Unknown")
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

        stats = {
            "meta": {
                "generated_at": timestamp.isoformat(),
                "generator": "ARGUN CTI v2.0",
            },
            "summary": {
                "total_cves": total_cves,
                "critical_count": critical_count,
                "high_count": high_count,
                "kev_count": kev_count,
                "poc_count": poc_count,
                "total_ips": len(ip_data),
            },
            "severity_distribution": severity_dist,
            "top_vendors": [{"vendor": v, "count": c} for v, c in top_vendors],
            "top_cwes": [{"cwe": c, "count": n} for c, n in top_cwes],
            "mitre_tactics": tactic_counts,
        }

        path = os.path.join(self.output_dir, "stats.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(stats, f, ensure_ascii=False, default=str)
        logger.info(f"  → Generated {path}")
