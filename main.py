#!/usr/bin/env python3
"""
ARGUN CTI — Cyber Threat Intelligence Platform
Main Data Pipeline Orchestrator

Collects CVE data from multiple sources, enriches with threat intelligence,
calculates ARGUN Threat Score (ATS), and outputs JSON for the frontend.

Author: ARGUN Security (www.argunsec.com)
"""

import json
import os
import sys
import logging
from datetime import datetime, timezone

from collectors.nvd_collector import NVDCollector
from collectors.kev_collector import KEVCollector
from collectors.epss_collector import EPSSCollector
from collectors.fedi_collector import FediCollector
from collectors.poc_collector import PoCCollector
from collectors.ip_collector import IPCollector
from enrichment.ats_scorer import ATSScorer
from enrichment.mitre_mapper import MITREMapper
from output.json_generator import JSONGenerator

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("argun-cti")


def main():
    logger.info("=" * 60)
    logger.info("ARGUN CTI — Data Pipeline Starting")
    logger.info("=" * 60)

    now = datetime.now(timezone.utc)
    cve_database = {}

    # ─── Phase 1: Collect CVE Data from NVD ───
    logger.info("[Phase 1/7] Collecting NVD data...")
    try:
        nvd = NVDCollector(api_key=os.environ.get("NVD_API_KEY"))
        nvd_cves = nvd.collect(hours_back=72)
        for cve_id, data in nvd_cves.items():
            cve_database[cve_id] = data
        logger.info(f"  → NVD: {len(nvd_cves)} CVEs collected")
    except Exception as e:
        logger.error(f"  → NVD collection failed: {e}")

    # ─── Phase 2: CISA KEV Enrichment ───
    logger.info("[Phase 2/7] Collecting CISA KEV data...")
    try:
        kev = KEVCollector()
        kev_set = kev.collect()
        for cve_id in cve_database:
            if cve_id in kev_set:
                cve_database[cve_id]["in_kev"] = True
                cve_database[cve_id]["kev_data"] = kev_set[cve_id]
        logger.info(f"  → KEV: {len(kev_set)} known exploited vulnerabilities loaded")
    except Exception as e:
        logger.error(f"  → KEV collection failed: {e}")

    # ─── Phase 3: EPSS Enrichment ───
    logger.info("[Phase 3/7] Collecting EPSS scores...")
    try:
        epss = EPSSCollector()
        epss_scores = epss.collect(list(cve_database.keys()))
        for cve_id, score_data in epss_scores.items():
            if cve_id in cve_database:
                cve_database[cve_id]["epss_score"] = score_data.get("epss", 0)
                cve_database[cve_id]["epss_percentile"] = score_data.get("percentile", 0)
        logger.info(f"  → EPSS: {len(epss_scores)} scores enriched")
    except Exception as e:
        logger.error(f"  → EPSS collection failed: {e}")

    # ─── Phase 4: FediSecFeeds + Social Signals ───
    logger.info("[Phase 4/7] Collecting social signals (Fediverse)...")
    try:
        fedi = FediCollector()
        fedi_data = fedi.collect()
        for cve_id, social in fedi_data.items():
            if cve_id in cve_database:
                cve_database[cve_id]["social_posts"] = social.get("posts", 0)
                cve_database[cve_id]["social_repos"] = social.get("repos", 0)
                cve_database[cve_id]["nuclei_template"] = social.get("nuclei", None)
                cve_database[cve_id]["fedi_updated"] = social.get("updated", None)
            else:
                # CVE found in Fedi but not in NVD — add it
                cve_database[cve_id] = {
                    "cve_id": cve_id,
                    "source": "fediverse",
                    "social_posts": social.get("posts", 0),
                    "social_repos": social.get("repos", 0),
                    "nuclei_template": social.get("nuclei", None),
                    "cvss_score": social.get("cvss", None),
                    "epss_score": social.get("epss", 0),
                    "description": social.get("description", ""),
                    "fedi_updated": social.get("updated", None),
                }
        logger.info(f"  → Fedi: {len(fedi_data)} CVEs with social signals")
    except Exception as e:
        logger.error(f"  → Fedi collection failed: {e}")

    # ─── Phase 5: PoC / Exploit Intelligence ───
    logger.info("[Phase 5/7] Checking exploit intelligence...")
    try:
        poc = PoCCollector()
        poc_data = poc.collect(list(cve_database.keys()))
        for cve_id, exploit_info in poc_data.items():
            if cve_id in cve_database:
                cve_database[cve_id]["has_poc"] = exploit_info.get("has_poc", False)
                cve_database[cve_id]["poc_urls"] = exploit_info.get("poc_urls", [])
                cve_database[cve_id]["nuclei_template"] = (
                    cve_database[cve_id].get("nuclei_template")
                    or exploit_info.get("nuclei_template")
                )
        logger.info(f"  → PoC: {len(poc_data)} CVEs with exploit data")
    except Exception as e:
        logger.error(f"  → PoC collection failed: {e}")

    # ─── Phase 6: MITRE ATT&CK Mapping ───
    logger.info("[Phase 6/7] Mapping MITRE ATT&CK techniques...")
    try:
        mitre = MITREMapper()
        for cve_id, data in cve_database.items():
            cwes = data.get("cwes", [])
            if cwes:
                techniques = mitre.map_cwe_to_attack(cwes)
                cve_database[cve_id]["mitre_techniques"] = techniques
        logger.info("  → MITRE mapping complete")
    except Exception as e:
        logger.error(f"  → MITRE mapping failed: {e}")

    # ─── Phase 7: Calculate ARGUN Threat Score ───
    logger.info("[Phase 7/7] Calculating ARGUN Threat Scores...")
    scorer = ATSScorer()
    for cve_id, data in cve_database.items():
        ats = scorer.calculate(data)
        cve_database[cve_id]["ats_score"] = ats["score"]
        cve_database[cve_id]["ats_level"] = ats["level"]
        cve_database[cve_id]["ats_breakdown"] = ats["breakdown"]

    # Count levels
    levels = {}
    for data in cve_database.values():
        lvl = data.get("ats_level", "INFO")
        levels[lvl] = levels.get(lvl, 0) + 1
    logger.info(f"  → ATS: {levels}")

    # ─── IP Threat Intelligence ───
    logger.info("Collecting IP threat intelligence...")
    ip_data = {}
    try:
        ip_collector = IPCollector()
        ip_data = ip_collector.collect()
        logger.info(f"  → IP Blacklist: {len(ip_data)} unique IPs collected")
    except Exception as e:
        logger.error(f"  → IP collection failed: {e}")

    # ─── Generate Output ───
    logger.info("Generating output files...")
    generator = JSONGenerator(output_dir="data")
    generator.generate_cve_feed(cve_database, now)
    generator.generate_ip_blacklist(ip_data, now)
    generator.generate_stats(cve_database, ip_data, now)
    generator.generate_blacklist_txt(ip_data)

    logger.info("=" * 60)
    logger.info(f"ARGUN CTI Pipeline Complete — {len(cve_database)} CVEs, {len(ip_data)} IPs")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
