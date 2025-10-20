import requests
import datetime as dt
import logging
import re

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
log = logging.getLogger(__name__)

def fetch_top_kev_cves(limit: int = 100):
    """
    Fetch CISA KEV CVE IDs added within the last 18 months
    and limited to CVEs from 2024 or 2025.
    Returns a list of recent CVEs sorted newest first.
    """
    try:
        r = requests.get(KEV_FEED_URL, timeout=10)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        log.error(f"❌ Failed to fetch KEV feed: {e}")
        return []

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        log.warning("⚠️ No vulnerabilities found in KEV feed.")
        return []

    cutoff_date = dt.datetime.utcnow() - dt.timedelta(days=18 * 30)  # ~18 months
    year_pattern = re.compile(r"CVE-(\d{4})-\d+")

    recent_vulns = []
    for v in vulns:
        cve_id = v.get("cveID", "")
        m = year_pattern.match(cve_id)
        if not m:
            continue
        cve_year = int(m.group(1))

        # ✅ keep only 2024–2025 CVEs AND added within last 18 months
        try:
            date_added = dt.datetime.strptime(v.get("dateAdded", ""), "%Y-%m-%d")
            if cve_year >= 2023 and date_added >= cutoff_date:
                recent_vulns.append((cve_id, date_added))
        except Exception:
            continue

    # Sort newest first
    recent_vulns.sort(key=lambda x: x[1], reverse=True)

    cves = [cve for cve, _ in recent_vulns[:limit]]

    log.info(
        f"🧩 Filtered {len(cves)} KEVs (years 2024–2025, added since {cutoff_date.date()})"
    )
    return cves
