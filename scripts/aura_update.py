#!/usr/bin/env python3
"""AURA update orchestrator — pulls KEV CVEs, enriches from NVD, EPSS, Exploit-DB, and scores."""

import os
import json
import datetime as dt
import logging
from typing import Any

from scripts.kev import fetch_top_kev_cves
from scripts.nvd import get_cvss_vendor_product
from scripts.epss import get_epss_score
from scripts.context import load_context, compute_context_fit
from scripts.ai_summary import summarize_cve
from scripts.scoring import compute_aura_score
from scripts.exploit_poc import has_exploit_poc  # returns (has_poc, edb_ids, urls)

# -------------------------------------------------------------------
# Config — all outputs go inside /public/data for web access
# -------------------------------------------------------------------
OUTPUT_SCORES = "public/data/aura_scores.json"
OUTPUT_MASTER = "public/data/aura_master.json"
HISTORY_DIR = "public/data/history"
CACHE_FILE = "data/cache/exploitdb.json"  # local cache
MAX_CVES = 10

logging.basicConfig(
    format="[%(asctime)s] %(message)s", level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def load_exploit_cache() -> dict:
    """Load cached Exploit-DB results. Normalizes older cache formats."""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r") as f:
            raw = json.load(f)
    except Exception:
        log.debug("Failed to load exploit cache (corrupt?), starting fresh.")
        return {}

    # Normalize entries:
    # - older format: cache[cve] = [found_bool, urls_list]
    # - new format: cache[cve] = [found_bool, edb_ids_list, urls_list]
    normalized: dict[str, Any] = {}
    for k, v in (raw.items() if isinstance(raw, dict) else []):
        if isinstance(v, list):
            if len(v) == 3:
                normalized[k] = v
            elif len(v) == 2:
                # upgrade: try to extract EDB ids from URLs if present
                found, urls = v
                edb_ids = []
                if isinstance(urls, list):
                    for u in urls:
                        # try extract numeric id from /exploits/<id>
                        try:
                            import re

                            m = re.search(r"/exploits/(\d+)", u)
                            if m:
                                edb_ids.append(m.group(1))
                        except Exception:
                            pass
                normalized[k] = [found, edb_ids, urls]
            else:
                # unknown shape -> skip
                normalized[k] = [False, [], []]
        else:
            normalized[k] = [False, [], []]
    return normalized


def save_exploit_cache(cache: dict):
    """Save updated cache to disk (atomic-ish)."""
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    tmp = CACHE_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(cache, f, indent=2)
        os.replace(tmp, CACHE_FILE)
    except Exception:
        try:
            with open(CACHE_FILE, "w") as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            log.warning(f"Failed to write exploit cache: {e}")


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
def main():
    ctx = load_context()
    exploit_cache = load_exploit_cache()
    log.info("🚀 Starting AURA update run")

    try:
        cves = fetch_top_kev_cves(MAX_CVES)
        log.info(f"✅ Retrieved {len(cves)} KEV CVEs: {', '.join(cves)}")
    except Exception as e:
        log.error(f"❌ Failed to fetch KEV feed: {e}")
        return

    records: list[dict] = []
    updated_cache = False

    for cve in cves:
        try:
            # --- Enrichment ---
            cvss, vendor, product = get_cvss_vendor_product(cve)
            epss = get_epss_score(cve)
            vendor = vendor or "Unknown"
            product = product or "Unknown"
            desc = f"{vendor} {product}"

            # --- Exploit-DB PoC check (EDB-ID + URLs) with caching ---
            if cve in exploit_cache:
                # expect [found_bool, edb_ids_list, urls_list]
                cached = exploit_cache[cve]
                # normalization safety
                if isinstance(cached, list) and len(cached) == 3:
                    exploit_found, exploit_edb_ids, exploit_urls = cached
                elif isinstance(cached, list) and len(cached) == 2:
                    # older shape: [found, urls]
                    exploit_found, exploit_urls = cached
                    # derive edb ids from urls
                    exploit_edb_ids = []
                    if isinstance(exploit_urls, list):
                        import re

                        for u in exploit_urls:
                            m = re.search(r"/exploits/(\d+)", u)
                            if m:
                                exploit_edb_ids.append(m.group(1))
                else:
                    exploit_found, exploit_edb_ids, exploit_urls = False, [], []
            else:
                exploit_found, exploit_edb_ids, exploit_urls = has_exploit_poc(cve)
                # ensure types
                exploit_found = bool(exploit_found)
                exploit_edb_ids = exploit_edb_ids or []
                exploit_urls = exploit_urls or []
                exploit_cache[cve] = [exploit_found, exploit_edb_ids, exploit_urls]
                updated_cache = True

            # --- Context and AI Summary ---
            ctx_mult = compute_context_fit(cve, vendor, product, desc, ctx)
            summary = summarize_cve(cve, vendor, product, desc, ctx)

            # --- Scoring ---
            aura_score = compute_aura_score(cvss, epss=epss, kev=True, ctx_mult=ctx_mult)

            score_breakdown = {
                "cvss_weight": 0.4,
                "epss_weight": 0.2,
                "kev_weight": 0.2,
                "exploit_weight": 0.1,
                "trend_weight": 0.05,
                "ai_weight": 0.05,
            }

            # --- Final Record ---
            record = {
                "cve": cve,
                "aura_score": aura_score,
                "cvss": round(cvss or 0, 1),
                "epss": round(epss or 0, 3),
                "kev": True,
                "exploit_poc": exploit_found,
                "exploit_edb_ids": exploit_edb_ids,
                "exploit_urls": exploit_urls,
                "trend_mentions": 0,
                "ai_context": 0.0,
                "vendor": vendor,
                "product": product,
                "summary": summary,
                "description": summary,
                "score_breakdown": score_breakdown,
            }

            records.append(record)
            log.info(
                f"✅ {cve} | CVSS {cvss:.1f} | EPSS {epss:.3f} | Exploit-DB: {exploit_found} | EDB IDs: {exploit_edb_ids}"
            )

        except Exception as e:
            log.warning(f"⚠️ Failed to process {cve}: {e}")

    # --- Save cache if updated ---
    if updated_cache:
        save_exploit_cache(exploit_cache)
        log.info(f"💾 Updated Exploit-DB cache with {len(exploit_cache)} entries")

    # --- Save outputs ---
    os.makedirs(os.path.dirname(OUTPUT_SCORES), exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_MASTER), exist_ok=True)

    today = dt.date.today().isoformat()
    try:
        with open(OUTPUT_SCORES, "w") as f:
            json.dump(records, f, indent=2)
        with open(OUTPUT_MASTER, "w") as f:
            json.dump({"date": today, "records": records}, f, indent=2)
        with open(os.path.join(HISTORY_DIR, f"{today}.json"), "w") as f:
            json.dump(records, f, indent=2)
    except Exception as e:
        log.error(f"Failed to write output files: {e}")
        return

    log.info(f"✅ Saved Top {len(records)} CVEs to {OUTPUT_SCORES}")
    log.info(f"📅 History snapshot written to {HISTORY_DIR}/{today}.json")


if __name__ == "__main__":
    main()
