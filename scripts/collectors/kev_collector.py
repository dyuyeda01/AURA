# scripts/collectors/kev_collector.py (live)
import requests, time

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"

def get_kev_data(timeout=30):
    r = requests.get(KEV_URL, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    # cisagov mirror schema: data['vulnerabilities'] or adjust per feed
    if isinstance(data, dict) and 'vulnerabilities' in data:
        return data['vulnerabilities']
    # fallback: return list if different shape
    return data
