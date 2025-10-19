import os
import json
import time
import logging
import requests
from typing import Tuple, Any

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

CACHE_DIR = "data/cache"
CACHE_TTL_DAYS = 7  # refresh every 7 days

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def dget(obj: Any, key: str, default=None):
    """Safe dict getter that avoids .get() on lists or non-dicts."""
    return obj.get(key, default) if isinstance(obj, dict) else default


def flatten_vuln_list(data: Any) -> list[dict]:
    """Recursively flatten any nested structure into a list of dicts."""
    out: list[dict] = []
    if isinstance(data, dict):
        out.append(data)
    elif isinstance(data, list):
        for item in data:
            out.extend(flatten_vuln_list(item))
    return out


def _extract_vendor_product_from_cpes(cve_obj: dict) -> Tuple[str, str]:
    """Derive vendor/product from NVD CPE configuration data (handles list/dict)."""
    vendor, product = "Unknown", "Unknown"
    configs = dget(cve_obj, "configurations", [])
    if isinstance(configs, dict):
        configs = [configs]

    def scan(nodes_list: list[dict]) -> Tuple[str, str] | None:
        for node in nodes_list:
            if not isinstance(node, dict):
                continue
            for match in dget(node, "cpeMatch", []) or []:
                crit = dget(match, "criteria") or dget(match, "cpe23Uri") or ""
                if isinstance(crit, str) and crit.startswith("cpe:2.3:"):
                    parts = crit.split(":")
                    if len(parts) >= 5:
                        v, p = parts[3], parts[4]
                        if v and v != "*" and p and p != "*":
                            return v, p
            children = dget(node, "children", [])
            if children:
                found = scan(children)
                if found:
                    return found
        return None

    for cfg in configs:
        nodes = dget(cfg, "nodes", [])
        found = scan(nodes)
        if found:
            return found

    return vendor, product


def normalize_name(name: str) -> str:
    """Clean and humanize vendor/product strings."""
    if not name or name == "Unknown":
        return "Unknown"
    name = name.replace("_", " ").strip()
    if len(name) < 4 or name.isupper():
        return name.title()
    return " ".join(w.capitalize() for w in name.split())


def cache_path_for(cve_id: str) -> str:
    """Return the cache file path for a CVE."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, f"{cve_id}.json")


def cache_is_valid(path: str) -> bool:
    """Check if cache file exists and is younger than TTL."""
    if not os.path.exists(path):
        return False
    age_days = (time.time() - os.path.getmtime(path)) / 86400
    return age_days < CACHE_TTL_DAYS


# -------------------------------------------------------------------
# Main NVD Lookup
# -------------------------------------------------------------------
def get_cvss_vendor_product(cve_id: str) -> Tuple[float, str, str]:
    """
    Query NVD for CVSS and vendor/product.
    Uses local cache for speed and auto-refreshes after TTL.
    """
    params = {"cveId": cve_id}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    cache_file = cache_path_for(cve_id)

    data = None
    if cache_is_valid(cache_file):
        try:
            with open(cache_file, "r") as f:
                data = json.load(f)
            log.info(f"[CACHE] Using cached NVD data for {cve_id}")
        except Exception as e:
            log.warning(f"[WARN] Failed to read cache for {cve_id}: {e}")
            data = None

    # Fetch if no valid cache
    if data is None:
        try:
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=25)
            if r.status_code == 403:
                log.warning(f"[WARN] NVD denied access for {cve_id} (403). Check API key or rate limits.")
                return 0.0, "Unknown", "Unknown"

            r.raise_for_status()
            data = r.json()

            # Cache response
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)
            log.info(f"[CACHE] Saved NVD data for {cve_id}")
        except Exception as e:
            log.warning(f"⚠️ NVD lookup failed for {cve_id}: {e}")
            return 0.0, "Unknown", "Unknown"

    # Unwrap lists
    if isinstance(data, list):
        data = data[0]

    vulns_raw = dget(data, "vulnerabilities") or dget(data, "CVE_Items") or []
    vulns = [v for v in flatten_vuln_list(vulns_raw) if isinstance(v, dict)]
    if not vulns:
        log.warning(f"[WARN] Empty or invalid NVD data for {cve_id}")
        return 0.0, "Unknown", "Unknown"

    cve = dget(vulns[0], "cve", vulns[0])
    if not isinstance(cve, dict):
        return 0.0, "Unknown", "Unknown"

    # -----------------------------
    # Extract CVSS
    # -----------------------------
    metrics = dget(cve, "metrics", {})
    score = 0.0
    if isinstance(metrics, dict):
        for key in ("cvssMetricV31", "cvssMetricV3", "cvssMetricV30", "cvssMetricV2"):
            metric = dget(metrics, key)
            if isinstance(metric, list) and metric:
                cvss_data = dget(metric[0], "cvssData", {})
                try:
                    score = float(dget(cvss_data, "baseScore", 0) or 0)
                except Exception:
                    score = 0.0
                break

    # -----------------------------
    # Extract Vendor/Product
    # -----------------------------
    vendor, product = _extract_vendor_product_from_cpes(cve)

    # Modern schema: containers.cna.affected
    if vendor == "Unknown" and product == "Unknown":
        containers = dget(cve, "containers", {})
        cna = dget(containers, "cna", {})
        affected = dget(cna, "affected", [])
        if isinstance(affected, list) and affected:
            first_aff = affected[0]
            vendor = dget(first_aff, "vendor") or vendor
            product = dget(first_aff, "product") or product

    # Legacy fallback
    if vendor == "Unknown" and product == "Unknown":
        vendor = dget(cve, "vendorProject") or vendor
        product = dget(cve, "product") or product

    # -----------------------------
    # Normalize for output
    # -----------------------------
    vendor = normalize_name(vendor)
    product = normalize_name(product)

    # -----------------------------
    # Debug dump if still unknown
    # -----------------------------
    if vendor == "Unknown" and product == "Unknown":
        os.makedirs("data/debug", exist_ok=True)
        debug_path = f"data/debug/{cve_id}.json"
        try:
            with open(debug_path, "w") as dbg:
                json.dump(data, dbg, indent=2)
            log.info(f"[DEBUG] Saved raw NVD data for {cve_id} → {debug_path}")
        except Exception as dbg_err:
            log.warning(f"[WARN] Could not write debug JSON for {cve_id}: {dbg_err}")

    return score, vendor, product
