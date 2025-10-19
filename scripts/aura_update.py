#!/usr/bin/env python3
"""
AURA Update Script v2
- Pulls last 100 CVEs from CISA KEV feed.
- Enriches each CVE with CVSS, vendor/product (NVD), and context-aware AI summary.
- Scores with weighted metrics (CVSS, KEV, EPSS, Exploit PoC, Trend, AI Context).
- Keeps top 10 by AURA score for dashboard output.

Env Vars:
  - NVD_API_KEY
  - OPENAI_API_KEY
  - AURA_MAX_KEV=100
  - AURA_TOP_N=10
  - AURA_CONTEXT=data/context.yaml
"""

import os, json, yaml, logging, datetime as dt, requests
from typing import Tuple, Optional, List

try:
    from openai import OpenAI
except Exception:
    OpenAI = None  # fallback if SDK missing

# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_SCORES = "public/data/aura_scores.json"
OUTPUT_MASTER = "data/aura_master.json"
HISTORY_DIR = "data/history"

MAX_KEV = int(os.getenv("AURA_MAX_KEV", 100))
TOP_N = int(os.getenv("AURA_TOP_N", 10))
CONTEXT_PATH = os.getenv("AURA_CONTEXT", "data/context.yaml")

W_CVSS, W_EPSS, W_KEV, W_EXPLOIT, W_TREND, W_AI = 0.4, 0.2, 0.2, 0.1, 0.05, 0.05

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
logging.basicConfig(format="[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S", level=logging.INFO)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Keys / Clients
# ---------------------------------------------------------------------
NVD_API_KEY = os.getenv("NVD_API_KEY")
if NVD_API_KEY: log.info("✅ Loaded NVD_API_KEY")
else: log.warning("⚠️ Missing NVD_API_KEY — may limit NVD lookups.")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if OPENAI_API_KEY and OpenAI:
    oai_client = OpenAI(api_key=OPENAI_API_KEY)
    log.info("✅ Loaded OpenAI API Key")
else:
    oai_client = None
    log.info("🔇 OpenAI summaries disabled.")

# ---------------------------------------------------------------------
# Context loader
# ---------------------------------------------------------------------
def load_context(path: str) -> dict:
    if not os.path.exists(path):
        log.info("ℹ️ No context.yaml found — using neutral context.")
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}

context = load_context(CONTEXT_PATH)

# ---------------------------------------------------------------------
# Vendor/product extraction from NVD
# ---------------------------------------------------------------------
def _extract_vendor_product_from_cpes(cve_obj: dict) -> Tuple[str, str]:
    vendor, product = "Unknown", "Unknown"
    configs = cve_obj.get("configurations", [])
    if not isinstance(configs, list): return vendor, product

    def walk(nodes):
        for n in nodes:
            for m in n.get("cpeMatch", []):
                cpe = m.get("criteria") or m.get("cpe23Uri") or ""
                if cpe.startswith("cpe:2.3:"):
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        v, p = parts[3], parts[4]
                        if v != "*" and p != "*": return v, p
            if isinstance(n.get("children"), list):
                found = walk(n["children"])
                if found: return found
        return None

    for c in configs:
        nodes = c.get("nodes", [])
        found = walk(nodes)
        if found: return found
    return vendor, product

# ---------------------------------------------------------------------
# NVD lookup
# ---------------------------------------------------------------------
def get_cvss_vendor_product(cve_id: str) -> Tuple[float, str, str]:
    params = {"cveId": cve_id}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=25)
        if r.status_code == 403:
            log.warning(f"403 for {cve_id} — check NVD key.")
            return 0.0, "Unknown", "Unknown"
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities") or []
        if not vulns: return 0.0, "Unknown", "Unknown"
        cve_obj = vulns[0].get("cve") or {}

        metrics = cve_obj.get("metrics") or {}
        score = 0.0
        if "cvssMetricV31" in metrics:
            score = float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])
        elif "cvssMetricV3" in metrics:
            score = float(metrics["cvssMetricV3"][0]["cvssData"]["baseScore"])
        elif "cvssMetricV2" in metrics:
            score = float(metrics["cvssMetricV2"][0]["cvssData"]["baseScore"])

        v, p = _extract_vendor_product_from_cpes(cve_obj)
        return score, v, p
    except Exception as e:
        log.warning(f"NVD lookup failed for {cve_id}: {e}")
        return 0.0, "Unknown", "Unknown"

# ---------------------------------------------------------------------
# Context fit scoring (RAG-lite)
# ---------------------------------------------------------------------
def compute_context_fit(cve_text: str, vendor: str, product: str) -> float:
    if not context: return 0.0
    text = f"{vendor} {product} {cve_text}".lower()
    score = 0.0

    for item in context.get("os", []):
        if item.lower() in text: score += 0.2
    for item in context.get("critical_products", []):
        if item.lower() in text: score += 0.4
    for item in context.get("cloud", []):
        if item.lower() in text: score += 0.2
    for word in str(context.get("sector", "")).split():
        if word.lower() in text: score += 0.1

    return min(score, 1.0)

# ---------------------------------------------------------------------
# AI summary
# ---------------------------------------------------------------------
def summarize_cve(cve: str, vendor: str, product: str, cve_desc: str, context_fit: float) -> str:
    if oai_client is None:
        return f"{cve}: {vendor} {product} — apply mitigations and patch promptly."
    try:
        ctx_str = json.dumps(context, ensure_ascii=False)
        prompt = (
            f"Context: {ctx_str}\n"
            f"Given CVE {cve} affecting {vendor} {product}, summarize risk and action "
            f"in 2-3 sentences for a cybersecurity team. "
            f"BaseScore contextFit={context_fit:.2f}. Keep it concise."
        )
        resp = oai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        log.warning(f"AI summary failed for {cve}: {e}")
        return f"{cve}: prioritize vendor patching and review exposures."

# ---------------------------------------------------------------------
# AURA composite scoring
# ---------------------------------------------------------------------
def compute_aura_score(cvss, kev, epss=0.0, exploit=False, trend=0.0, ai=0.0):
    cvss = max(0.0, min(10.0, cvss))
    epss_100 = max(0.0, min(100.0, epss * 100))
    kev_100 = 100.0 if kev else 0.0
    exploit_100 = 100.0 if exploit else 0.0
    trend_100 = max(0.0, min(100.0, trend))
    ai_100 = max(0.0, min(100.0, ai * 100))
    score = (
        cvss * 10 * W_CVSS +
        epss_100 * W_EPSS +
        kev_100 * W_KEV +
        exploit_100 * W_EXPLOIT +
        trend_100 * W_TREND +
        ai_100 * W_AI
    )
    return round(score, 1)

# ---------------------------------------------------------------------
# KEV fetcher
# ---------------------------------------------------------------------
def fetch_kev():
    log.info(f"📡 Fetching KEV feed ({MAX_KEV} max)")
    data = requests.get(KEV_URL, timeout=30).json()
    vulns = data.get("vulnerabilities", [])
    vulns = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)
    return vulns[:MAX_KEV]

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main():
    log.info("🚀 Starting AURA update run")
    kev_data = fetch_kev()
    cves = [v["cveID"] for v in kev_data if "cveID" in v]

    records = []
    for v in kev_data:
        cve = v["cveID"]
        vendor = v.get("vendorProject", "Unknown")
        product = v.get("product", "Unknown")
        cvss, nvd_vendor, nvd_product = get_cvss_vendor_product(cve)
        if vendor == "Unknown" and product == "Unknown":
            vendor, product = nvd_vendor, nvd_product
        desc = v.get("shortDescription", "")
        context_fit = compute_context_fit(desc, vendor, product)
        summary = summarize_cve(cve, vendor, product, desc, context_fit)

        aura = compute_aura_score(cvss, kev=True, ai=context_fit)

        record = {
            "cve": cve,
            "aura_score": aura,
            "cvss": cvss,
            "epss": 0.0,
            "kev": True,
            "exploit_poc": False,
            "trend_mentions": 0,
            "ai_context": context_fit,
            "vendor": vendor,
            "product": product,
            "summary": summary,
            "description": desc,
            "score_breakdown": {
                "cvss_weight": W_CVSS,
                "epss_weight": W_EPSS,
                "kev_weight": W_KEV,
                "exploit_weight": W_EXPLOIT,
                "trend_weight": W_TREND,
                "ai_weight": W_AI
            }
        }
        records.append(record)
        log.info(f"✅ {cve} ({vendor} {product}) aura={aura}")

    # Rank + slice top N
    top = sorted(records, key=lambda x: x["aura_score"], reverse=True)[:TOP_N]

    os.makedirs(os.path.dirname(OUTPUT_SCORES), exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    today = dt.date.today().isoformat()

    json.dump(top, open(OUTPUT_SCORES, "w"), indent=2)
    json.dump({"date": today, "records": records}, open(OUTPUT_MASTER, "w"), indent=2)
    json.dump(records, open(f"{HISTORY_DIR}/{today}.json", "w"), indent=2)
    log.info(f"✅ Saved Top {len(top)} CVEs to {OUTPUT_SCORES}")
    log.info(f"📅 History snapshot written to {HISTORY_DIR}/{today}.json")

if __name__ == "__main__":
    main()
