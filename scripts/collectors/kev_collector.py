# scripts/collectors/kev_collector.py
def get_kev_data():
    # Placeholder data. Replace with live KEV pull later.
    # Example live:
    # import requests
    # url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    # return requests.get(url, timeout=30).json().get("vulnerabilities", [])
    return [
        {
            "cve": "CVE-2024-12345",
            "vendor": "Cisco",
            "product": "IOS XE",
            "description": "Sample KEV entry: RCE in Cisco IOS XE web UI.",
            "kev": True,
            "date_added": "2025-10-10"
        },
        {
            "cve": "CVE-2024-56789",
            "vendor": "Microsoft",
            "product": "Exchange Server",
            "description": "Sample KEV entry: Privilege escalation in Exchange.",
            "kev": True,
            "date_added": "2025-10-12"
        },
        {
            "cve": "CVE-2024-33333",
            "vendor": "Fortinet",
            "product": "FortiOS",
            "description": "Sample KEV entry: Web UI auth bypass in FortiOS.",
            "kev": True,
            "date_added": "2025-10-14"
        }
    ]
