# scripts/collectors/nvd_collector.py
def get_cvss(cve: str) -> float:
    # Placeholder CVSS. Replace with live NVD REST API later.
    # Live example:
    # import requests
    # url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?cveId={cve}"
    # data = requests.get(url, timeout=30).json()
    # ... extract CVSSv3 baseScore ...
    mock = {
        "CVE-2024-12345": 9.8,
        "CVE-2024-56789": 8.2,
        "CVE-2024-33333": 8.8,
    }
    return mock.get(cve, 7.0)
