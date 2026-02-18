"""
ARGUN CTI — ARGUN Threat Score (ATS) Calculator
Composite risk scoring algorithm combining multiple threat dimensions.

Score Dimensions:
  1. Technical Severity (CVSS)      — Max 30 pts
  2. Exploit Probability (EPSS)     — Max 25 pts
  3. Weaponization Status           — Max 20 pts
  4. Social Signal / Buzz           — Max 15 pts
  5. Time Factor (recency)          — Max 10 pts

Total: 0-100
"""

import logging

logger = logging.getLogger("argun-cti.ats")

# ATS Level Thresholds
LEVELS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0, "INFO"),
]


class ATSScorer:
    def calculate(self, cve_data):
        """
        Calculate ARGUN Threat Score for a single CVE.
        Returns: { score: int, level: str, breakdown: dict }
        """
        breakdown = {}

        # ─── 1. Technical Severity (Max 30) ───
        cvss = cve_data.get("cvss_score") or 0
        try:
            cvss = float(cvss)
        except (ValueError, TypeError):
            cvss = 0
        severity_score = round((cvss / 10) * 30, 1)
        breakdown["severity"] = severity_score

        # ─── 2. Exploit Probability (Max 25) ───
        epss = cve_data.get("epss_score") or 0
        try:
            epss = float(epss)
        except (ValueError, TypeError):
            epss = 0
        # EPSS is already 0-1, map to 0-25
        exploit_prob_score = round(epss * 25, 1)
        breakdown["exploit_probability"] = exploit_prob_score

        # ─── 3. Weaponization Status (Max 20) ───
        weapon_score = 0
        if cve_data.get("in_kev"):
            weapon_score += 8  # Known exploited = highest signal
        if cve_data.get("has_poc"):
            weapon_score += 5  # Public PoC exists
        if cve_data.get("nuclei_template"):
            weapon_score += 4  # Nuclei template = automated exploitation possible
        if cve_data.get("social_repos", 0) >= 1:
            weapon_score += 3  # GitHub repos discussing/exploiting
        weapon_score = min(weapon_score, 20)
        breakdown["weaponization"] = weapon_score

        # ─── 4. Social Signal (Max 15) ───
        posts = cve_data.get("social_posts", 0) or 0
        repos = cve_data.get("social_repos", 0) or 0

        social_score = 0
        if posts >= 15:
            social_score += 9
        elif posts >= 8:
            social_score += 7
        elif posts >= 4:
            social_score += 5
        elif posts >= 2:
            social_score += 3
        elif posts >= 1:
            social_score += 1

        if repos >= 5:
            social_score += 6
        elif repos >= 3:
            social_score += 4
        elif repos >= 1:
            social_score += 2

        social_score = min(social_score, 15)
        breakdown["social_signal"] = social_score

        # ─── 5. Time Factor (Max 10) ───
        days = cve_data.get("days_since_publish", 999)
        if days is None:
            days = 999

        time_score = 0
        if days <= 1:
            time_score = 10  # Last 24h — breaking
        elif days <= 3:
            time_score = 8
        elif days <= 7:
            time_score = 6
        elif days <= 14:
            time_score = 4
        elif days <= 30:
            time_score = 2
        else:
            time_score = 0

        breakdown["time_factor"] = time_score

        # ─── Total Score ───
        total = severity_score + exploit_prob_score + weapon_score + social_score + time_score
        total = min(round(total), 100)

        # Determine level
        level = "INFO"
        for threshold, level_name in LEVELS:
            if total >= threshold:
                level = level_name
                break

        return {
            "score": total,
            "level": level,
            "breakdown": breakdown,
        }
