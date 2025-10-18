# scripts/collectors/epss_collector.py
def get_epss_score(cve: str) -> float:
    # Placeholder EPSS. Replace with live FIRST.org EPSS API later.
    # Live example:
    # import requests
    # api = f"https://api.first.org/data/v1/epss?cve={cve}"
    # data = requests.get(api, timeout=15).json()
    # return float(data["data"][0]["epss"])
    mock = {
        "CVE-2024-12345": 0.86,
        "CVE-2024-56789": 0.72,
        "CVE-2024-33333": 0.64,
    }
    return mock.get(cve, 0.3)
