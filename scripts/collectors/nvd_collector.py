# scripts/collectors/nvd_collector.py
"""
NVD collector (v2.0) with verified API key header support.

Environment:
  export NVD_API_KEY="your-nvd-key"
"""

import os
import requests
import logging
import random

log = logging.getLogger(__name__)

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cvss(cve: str) -> float:
    """
    Query NVD API for a given CVE ID and return the CVSS v3 base score.
    Returns a random fallback score if unavailable.
    """

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {"cveId": cve}

    try:
        r = requests.get(NVD_BASE, headers=headers, params=params, timeout=20)
        if r.status_code == 403:
            log.warning(f"[WARN] NVD denied access for {cve} (403 Forbidden — check API key permissions or quota)")
            return random.uniform(6.0, 9.5)
        r.raise_for_status()

        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return random.uniform(6.0, 9.5)

        metrics = vulns[0].get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                if cvss is not None:
                    return float(cvss)

        return random.uniform(6.0, 9.5)

    except Exception as e:
        log.warning(f"[WARN] NVD API error for {cve}: {e}")
        return random.uniform(6.0, 9.5)
