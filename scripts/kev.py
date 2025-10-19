import requests, logging
log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_top_kev_cves(limit: int = 10) -> list[str]:
    log.info(f"📡 Fetching KEV feed from {KEV_URL}")
    r = requests.get(KEV_URL, timeout=30)
    r.raise_for_status()
    data = r.json()
    vulns = data.get("vulnerabilities") or []
    return [v.get("cveID") for v in vulns if v.get("cveID")][:limit]
