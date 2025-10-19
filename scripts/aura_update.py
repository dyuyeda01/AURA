#!/usr/bin/env python3
"""
AURA Update Script
- Pull CVEs from CISA KEV feed (top N).
- Enrich each CVE with CVSS and vendor/product from NVD v2.0 API.
- Generate a short AI summary (optional; requires OPENAI_API_KEY).
- Write outputs for the web UI:
    - public/data/aura_scores.json    (list for today's dashboard)
    - data/history/YYYY-MM-DD.json    (daily snapshot)
    - data/aura_master.json           (simple master with today's records)

ENV:
  - NVD_API_KEY      (required for reliable NVD calls)
  - OPENAI_API_KEY   (optional; summaries)
"""

from __future__ import annotations

import os
import json
import logging
import datetime as dt
from typing import Tuple, Optional, List

import requests

# OpenAI is optional
try:
    from openai import OpenAI
except Exception:
    OpenAI = None  # type: ignore

# -------------------------
# Config
# -------------------------
MAX_CVES = 10
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

OUTPUT_SCORES = "public/data/aura_scores.json"
HISTORY_DIR = "data/history"
OUTPUT_MASTER = "data/aura_master.json"

# Scoring weights (leave as-is; wire data sources later)
W_CVSS   = 0.40   # CVSS (0-10 → *10 for 0-100)
W_EPSS   = 0.20   # EPSS (0-1 → *100)
W_KEV    = 0.20   # KEV boolean (Yes→100, No→0)
W_EXPLOIT= 0.10   # PoC boolean
W_TREND  = 0.05   # normalize mentions to 0-100 upstream
W_AI     = 0.05   # AI context (0-1 → *100)

# -------------------------
# Logging
# -------------------------
logging.basicConfig(
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

# -------------------------
# Keys / Clients
# -------------------------
NVD_API_KEY = os.getenv("NVD_API_KEY")
if NVD_API_KEY:
    log.info("✅ Loaded NVD_API_KEY")
else:
    log.warning("⚠️ Missing NVD_API_KEY — NVD lookups may be limited/blocked.")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if OPENAI_API_KEY and OpenAI is not None:
    log.info("✅ Loaded OpenAI API Key")
    oai_client = OpenAI(api_key=OPENAI_API_KEY)
else:
    oai_client = None
    log.info("🔇 OpenAI summaries disabled (no key or SDK).")

# -------------------------
# Helpers
# -------------------------
def _extract_vendor_product_from_cpes(cve_obj: dict) -> Tuple[str, str]:
    """
    Deeply extract vendor and product from CPE URIs in NVD v2.0 CVE object.
    Handles both 'configurations' (list) and nested node structures.
    """
    vendor, product = "Unknown", "Unknown"
    configs = cve_obj.get("configurations", [])
    if not isinstance(configs, list):
        return vendor, product

    def walk_nodes(nodes: list) -> Optional[Tuple[str, str]]:
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for match in cpe_matches:
                cpe = match.get("criteria") or match.get("cpe23Uri") or ""
                if cpe.startswith("cpe:2.3:"):
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        v = parts[3]
                        p = parts[4]
                        if v != "*" and p != "*":
                            return v, p
            # Recurse children
            if "children" in node and isinstance(node["children"], list):
                found = walk_nodes(node["children"])
                if found:
                    return found
        return None

    # Top-level configs
    for config in configs:
        nodes = config.get("nodes", [])
        found = walk_nodes(nodes)
        if found:
            return found

    return vendor, product


def get_cvss_vendor_product(cve_id: str) -> Tuple[float, str, str]:
    """
    Query NVD v2.0 for a CVE's CVSS score and basic vendor/product info.
    Returns: (cvss_score, vendor, product)
    """
    params = {"cveId": cve_id}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    try:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=25)
        if r.status_code == 403:
            log.warning(f"[WARN] NVD denied access for {cve_id} (403). Check NVD_API_KEY or rate limits.")
            return 0.0, "Unknown", "Unknown"
        r.raise_for_status()
        data = r.json()

        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return 0.0, "Unknown", "Unknown"

        # v2.0 shape: [{ "cve": { ... } }]
        cve_entry = vulns[0].get("cve", {})
        metrics = cve_entry.get("metrics", {})
        score = 0.0

        # Extract CVSS base score (support multiple formats)
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3", "cvssMetricV2"):
            if key in metrics:
                m = metrics[key][0]["cvssData"]
                score = float(m["baseScore"])
                break

        # Try to pull vendor/product info
        vendor = cve_entry.get("vendorProject") or "Unknown"
        product = cve_entry.get("product") or "Unknown"

        # Sometimes it's buried in configurations (list, not dict)
        if vendor == "Unknown" and product == "Unknown":
            configs = cve_entry.get("configurations", [])
            for node in configs:
                matches = node.get("nodes", []) or node.get("cpeMatch", [])
                for match in matches:
                    cpe = match.get("criteria") or match.get("cpe23Uri") or ""
                    if cpe.startswith("cpe:2.3:"):
                        parts = cpe.split(":")
                        if len(parts) > 5:
                            vendor, product = parts[3], parts[4]
                            if vendor != "*" and product != "*":
                                break

        return score, vendor, product

    except Exception as e:
        log.warning(f"⚠️ NVD lookup failed for {cve_id}: {e}")
        return 0.0, "Unknown", "Unknown"


def summarize_cve(cve_id: str, vendor: str, product: str) -> str:
    """
    Short AI summary. If OpenAI is disabled, return a concise fallback.
    """
    if oai_client is None:
        vp = f"{vendor} {product}".strip()
        return f"{cve_id} affects {vp if vp != 'Unknown Unknown' else 'impacted products'}. Prioritize patching and apply vendor mitigations."

    try:
        prompt = (
            f"In 2 sentences, summarize the risk and recommended action for {cve_id}. "
            f"Vendor: {vendor}, Product: {product}. Be practical and concise."
        )
        resp = oai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception as e:
        log.warning(f"⚠️ AI summary failed for {cve_id}: {e}")
        return f"{cve_id}: apply vendor patches and mitigations promptly."


def compute_aura_score(
    cvss: float,
    kev: bool,
    epss: float = 0.0,
    exploit_poc: bool = False,
    trend_norm_0_100: float = 0.0,
    ai_context_0_1: float = 0.0,
) -> float:
    """
    Weighted composite => 0..100.
    For now, EPSS/exploit/trend/ai_context default to 0 until their collectors are wired.
    """
    cvss_0_100 = max(0.0, min(100.0, cvss * 10.0))
    epss_0_100 = max(0.0, min(100.0, epss * 100.0))
    kev_0_100 = 100.0 if kev else 0.0
    exploit_0_100 = 100.0 if exploit_poc else 0.0
    trend_0_100 = max(0.0, min(100.0, trend_norm_0_100))
    ai_0_100 = max(0.0, min(100.0, ai_context_0_1 * 100.0))

    score = (
        cvss_0_100 * W_CVSS +
        epss_0_100 * W_EPSS +
        kev_0_100 * W_KEV +
        exploit_0_100 * W_EXPLOIT +
        trend_0_100 * W_TREND +
        ai_0_100 * W_AI
    )
    return round(score, 1)


def fetch_top_kev_cves(limit: int = MAX_CVES) -> list[str]:
    """Return the latest KEV CVE IDs."""
    log.info(f"📡 Fetching KEV feed from {KEV_URL}")
    r = requests.get(KEV_URL, timeout=30)
    r.raise_for_status()
    data = r.json()
    vulns = data.get("vulnerabilities") or []
    # Keep order as published in KEV (typically latest first), then trim
    return [v.get("cveID") for v in vulns if v.get("cveID")][:limit]


# -------------------------
# Main
# -------------------------
def main():
    log.info("🚀 Starting AURA update run")

    # 1) Pick CVEs from KEV
    try:
        kev_data = requests.get(KEV_URL, timeout=30).json().get("vulnerabilities", [])
        cves = fetch_top_kev_cves(MAX_CVES)
        if not cves:
            log.error("❌ KEV returned no CVEs.")
            return
        log.info(f"✅ Retrieved {len(cves)} KEV CVEs: {', '.join(cves)}")
    except Exception as e:
        log.error(f"❌ Failed to fetch KEV feed: {e}")
        return

    # 2) Enrich and build records
    records = []
    for cve in cves:
        try:
            kev_entry = next((v for v in kev_data if v.get("cveID") == cve), {})
            vendor = kev_entry.get("vendorProject") or "Unknown"
            product = kev_entry.get("product") or "Unknown"

            cvss, nvd_vendor, nvd_product = get_cvss_vendor_product(cve)
            # Prefer KEV vendor/product if NVD didn’t provide
            if vendor == "Unknown" and product == "Unknown":
                vendor, product = nvd_vendor, nvd_product

            summary = summarize_cve(cve, vendor, product)


            kev_flag = True
            epss = 0.0            # TODO: wire FIRST EPSS
            exploit_poc = False   # TODO: wire ExploitDB / GitHub search
            trend_norm = 0.0      # TODO: wire news/social mentions (0..100)
            ai_context = 0.0      # TODO: compute from AI classifier (0..1)

            aura_score = compute_aura_score(
                cvss=cvss,
                kev=kev_flag,
                epss=epss,
                exploit_poc=exploit_poc,
                trend_norm_0_100=trend_norm,
                ai_context_0_1=ai_context,
            )

            record = {
                "cve": cve,
                "aura_score": compute_aura_score(cvss, kev=True),
                "cvss": cvss,
                "epss": 0.0,
                "kev": True,
                "exploit_poc": False,
                "trend_mentions": 0,
                "ai_context": 0.0,
                "vendor": vendor,
                "product": product,
                "summary": summary,
                "description": summary,
                "score_breakdown": {
                    "cvss_weight": 0.4,
                    "epss_weight": 0.2,
                    "kev_weight": 0.2,
                    "exploit_weight": 0.1,
                    "trend_weight": 0.05,
                    "ai_weight": 0.05
                }
            }

            records.append(record)
            log.info(f"✅ Processed {cve} (CVSS {cvss}, Vendor/Product: {vendor} {product})")

        except Exception as e:
            log.warning(f"⚠️ Failed to process {cve}: {e}")

    # 3) Persist outputs
    os.makedirs(os.path.dirname(OUTPUT_SCORES), exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_MASTER), exist_ok=True)

    today = dt.date.today().isoformat()

    with open(OUTPUT_SCORES, "w") as f:
        json.dump(records, f, indent=2)

    with open(OUTPUT_MASTER, "w") as f:
        json.dump({"date": today, "records": records}, f, indent=2)

    with open(os.path.join(HISTORY_DIR, f"{today}.json"), "w") as f:
        json.dump(records, f, indent=2)

    log.info(f"✅ Saved Top {len(records)} CVEs to {OUTPUT_SCORES}")
    log.info(f"📅 History snapshot written to {HISTORY_DIR}/{today}.json")


if __name__ == "__main__":
    main()
