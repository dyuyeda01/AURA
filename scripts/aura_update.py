#!/usr/bin/env python3
"""AURA update orchestrator — pulls KEV CVEs, enriches from NVD, and scores."""

import os, json, datetime as dt, logging

from scripts.kev import fetch_top_kev_cves
from scripts.nvd import get_cvss_vendor_product
from scripts.context import load_context, compute_context_fit
from scripts.ai_summary import summarize_cve
from scripts.scoring import compute_aura_score

# -------------------------------------------------------------------
# Config — all outputs go inside /public/data for web access
# -------------------------------------------------------------------
OUTPUT_SCORES = "public/data/aura_scores.json"
OUTPUT_MASTER = "public/data/aura_master.json"
HISTORY_DIR = "public/data/history"
MAX_CVES = 10

logging.basicConfig(
    format="[%(asctime)s] %(message)s", level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
def main():
    ctx = load_context()
    log.info("🚀 Starting AURA update run")

    try:
        cves = fetch_top_kev_cves(MAX_CVES)
        log.info(f"✅ Retrieved {len(cves)} KEV CVEs: {', '.join(cves)}")
    except Exception as e:
        log.error(f"❌ Failed to fetch KEV feed: {e}")
        return

    records = []
    for cve in cves:
        try:
            cvss, vendor, product = get_cvss_vendor_product(cve)
            desc = f"{vendor} {product}"
            ctx_mult = compute_context_fit(cve, vendor, product, desc, ctx)
            summary = summarize_cve(cve, vendor, product, desc, ctx)
            aura_score = compute_aura_score(cvss, kev=True, ctx_mult=ctx_mult)

            # consistent weight values for front-end rendering
            score_breakdown = {
                "cvss_weight": 0.4,
                "epss_weight": 0.2,
                "kev_weight": 0.2,
                "exploit_weight": 0.1,
                "trend_weight": 0.05,
                "ai_weight": 0.05,
            }

            record = {
                "cve": cve,
                "aura_score": aura_score,
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
                "score_breakdown": score_breakdown,
            }
            records.append(record)
            log.info(f"✅ Processed {cve} (CVSS {cvss}, Vendor/Product: {vendor} {product})")

        except Exception as e:
            log.warning(f"⚠️ Failed to process {cve}: {e}")

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
