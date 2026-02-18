"""
ARGUN CTI — IP Threat Intelligence Aggregator
Collects malicious IPs from multiple open-source threat feeds.
Similar to karaliste.net but with more sources and enrichment.
"""

import requests
import logging
import re
from collections import defaultdict

logger = logging.getLogger("argun-cti.ip")

# ─── IP Feed Sources ───
IP_FEEDS = {
    "ipsum": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "parser": "ipsum",
        "category": "aggregated",
        "description": "30+ blacklist aggregation by stamparm",
    },
    "feodo_c2": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "parser": "comment_hash",
        "category": "c2",
        "description": "Feodo Tracker C2 IP Blocklist",
    },
    "blocklist_de": {
        "url": "https://www.blocklist.de/lists/all.txt",
        "parser": "plain",
        "category": "bruteforce",
        "description": "Blocklist.de fail2ban aggregation",
    },
    "emerging_threats": {
        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "parser": "comment_hash",
        "category": "malicious",
        "description": "Proofpoint Emerging Threats Block IPs",
    },
    "cins_army": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "parser": "plain",
        "category": "sentinel",
        "description": "CINS Army — Sentinel-based threat IPs",
    },
    "binary_defense": {
        "url": "https://www.binarydefense.com/banlist.txt",
        "parser": "plain",
        "category": "artillery",
        "description": "Binary Defense Artillery Threat IPs",
    },
    "abuse_sslbl": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "parser": "comment_hash",
        "category": "ssl_malware",
        "description": "abuse.ch SSL Blacklist IPs",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "parser": "urlhaus",
        "category": "malware_distribution",
        "description": "abuse.ch URLhaus malware URLs (IP extraction)",
    },
}

# IP regex pattern
IP_PATTERN = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
)
IP_EXTRACT_PATTERN = re.compile(
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)


class IPCollector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ARGUN-CTI/2.0"})

    def collect(self):
        """
        Collect IPs from all sources, deduplicate, and enrich.
        Returns: dict of IP → metadata
        """
        ip_database = defaultdict(lambda: {
            "ip": "",
            "sources": [],
            "categories": set(),
            "hit_count": 0,
            "first_seen": None,
        })

        for feed_name, feed_config in IP_FEEDS.items():
            logger.info(f"  Fetching {feed_name}...")
            try:
                ips = self._fetch_feed(feed_config)
                for ip, extra in ips:
                    ip_database[ip]["ip"] = ip
                    ip_database[ip]["sources"].append(feed_name)
                    ip_database[ip]["categories"].add(feed_config["category"])
                    ip_database[ip]["hit_count"] += 1
                    if extra.get("ipsum_count"):
                        # ipsum already has multi-source count
                        ip_database[ip]["hit_count"] = max(
                            ip_database[ip]["hit_count"],
                            extra["ipsum_count"]
                        )
                logger.info(f"    → {feed_name}: {len(ips)} IPs")
            except Exception as e:
                logger.warning(f"    → {feed_name} failed: {e}")

        # Convert sets to lists for JSON serialization
        result = {}
        for ip, data in ip_database.items():
            data["categories"] = list(data["categories"])
            # Only include IPs seen in 2+ sources OR in ipsum with count >= 3
            if data["hit_count"] >= 2:
                result[ip] = data

        logger.info(f"  Total unique IPs (confidence >= 2): {len(result)}")
        return result

    def _fetch_feed(self, config):
        """Fetch and parse a single IP feed."""
        resp = self.session.get(config["url"], timeout=30)
        resp.raise_for_status()
        text = resp.text

        parser = config["parser"]

        if parser == "ipsum":
            return self._parse_ipsum(text)
        elif parser == "plain":
            return self._parse_plain(text)
        elif parser == "comment_hash":
            return self._parse_comment_hash(text)
        elif parser == "urlhaus":
            return self._parse_urlhaus(text)
        else:
            return self._parse_plain(text)

    def _parse_ipsum(self, text):
        """Parse stamparm/ipsum format: IP<tab>count"""
        results = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                ip = parts[0].strip()
                try:
                    count = int(parts[1].strip())
                except ValueError:
                    count = 1
                if self._is_valid_ip(ip):
                    results.append((ip, {"ipsum_count": count}))
        return results

    def _parse_plain(self, text):
        """Parse plain IP list (one per line)."""
        results = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            match = IP_PATTERN.match(line)
            if match and self._is_valid_ip(match.group(1)):
                results.append((match.group(1), {}))
        return results

    def _parse_comment_hash(self, text):
        """Parse IP list with # comments."""
        results = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Some lines might have trailing comments
            ip_part = line.split("#")[0].strip()
            match = IP_PATTERN.match(ip_part)
            if match and self._is_valid_ip(match.group(1)):
                results.append((match.group(1), {}))
        return results

    def _parse_urlhaus(self, text):
        """Extract IPs from URLhaus URL list."""
        results = []
        seen = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Extract IP from URL
            match = IP_EXTRACT_PATTERN.search(line)
            if match:
                ip = match.group(1)
                if ip not in seen and self._is_valid_ip(ip):
                    results.append((ip, {}))
                    seen.add(ip)
        return results

    @staticmethod
    def _is_valid_ip(ip):
        """Basic IP validation."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
