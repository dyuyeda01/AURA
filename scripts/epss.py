# scripts/epss.py
"""EPSS integration for AURA — Fetches Exploit Prediction Scoring System data."""

import requests
import logging

log = logging.getLogger(__name__)
API_URL = "https://api.first.org/data/v1/epss"

def get_epss_score(cve_id: str) -> float:
    """Return the EPSS probability score (0.0–1.0) for a given CVE."""
    try:
        resp = requests.get(API_URL, params={"cve": cve_id}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if "data" in data and len(data["data"]) > 0:
            return float(data["data"][0].get("epss", 0.0))
    except Exception as e:
        log.warning(f"⚠️ EPSS fetch failed for {cve_id}: {e}")
    return 0.0
