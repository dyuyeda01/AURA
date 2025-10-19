# scripts/collectors/epss_collector.py (live)
import requests

def get_epss_score(cve):
    url = f"https://api.first.org/data/v1/epss?cve={cve}"
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    data = r.json()
    for d in data.get("data", []):
        if d.get("cve") == cve:
            return float(d.get("epss", 0.0))
    return 0.0
