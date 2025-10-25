#!/usr/bin/env python3
"""AURA update orchestrator — pulls KEV CVEs, enriches from NVD, EPSS, Exploit-DB, NewsAPI (Trend & Articles),
AI Context, and computes unified scores, then generates daily analyst & CISO summaries.
"""

import os
import re
import json
import math
import datetime as dt
import logging
from typing import Any, Optional
import requests
from openai import OpenAI

from scripts.kev import fetch_top_kev_cves
from scripts.nvd import get_cvss_vendor_product
from scripts.epss import get_epss_score
from scripts.context import load_context, compute_context_fit
from scripts.ai_summary import summarize_cve
from scripts.exploit_poc import has_exploit_poc
from scripts.scoring import compute_aura_score
from scripts.ai_context import compute_ai_context_score  # ✅ NEW

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------
OUTPUT_SCORES = "public/data/aura_scores.json"
OUTPUT_MASTER = "public/data/aura_master.json"
HISTORY_DIR = "public/data/history"
CACHE_FILE = "data/cache/exploitdb.json"
MAX_CVES = 12
NEWSAPI_KEY = os.getenv("NEWSAPI_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
NEWS_CAP = 50.0  # normalization cap for trend

logging.basicConfig(
    format="[%(asctime)s] %(message)s", level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)

client = None
if OPENAI_API_KEY:
    try:
        client = OpenAI(api_key=OPENAI_API_KEY)
        log.info("✅ OpenAI client initialized for daily summaries")
    except Exception as e:
        log.warning(f"⚠️ Failed to initialize OpenAI client: {e}")
else:
    log.warning("⚠️ No OPENAI_API_KEY found — summaries will be skipped")

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def load_exploit_cache() -> dict:
    """Load cached Exploit-DB results and normalize legacy formats."""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r") as f:
            raw = json.load(f)
    except Exception:
        log.debug("Failed to load exploit cache, starting fresh.")
        return {}

    normalized: dict[str, Any] = {}
    for k, v in (raw.items() if isinstance(raw, dict) else []):
        if isinstance(v, list):
            if len(v) == 3:
                normalized[k] = v
            elif len(v) == 2:
                found, urls = v
                edb_ids = []
                if isinstance(urls, list):
                    for u in urls:
                        m = re.search(r"/exploits/(\d+)", u)
                        if m:
                            edb_ids.append(m.group(1))
                normalized[k] = [found, edb_ids, urls]
            else:
                normalized[k] = [False, [], []]
        else:
            normalized[k] = [False, [], []]
    return normalized


def save_exploit_cache(cache: dict):
    """Persist exploit cache safely."""
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    tmp = CACHE_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(cache, f, indent=2)
        os.replace(tmp, CACHE_FILE)
    except Exception:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)


# 📰 ----------------------------------------------------------------
# News & Trend
# -------------------------------------------------------------------
def get_article_for_cve(cve_id: str) -> Optional[dict]:
    """Return the first relevant article URL for a CVE via NewsAPI."""
    if not NEWSAPI_KEY:
        return None
    try:
        url = "https://newsapi.org/v2/everything"
        params = {
            "q": f"\"{cve_id}\"",
            "sortBy": "relevancy",
            "language": "en",
            "pageSize": 1,
            "apiKey": NEWSAPI_KEY,
        }
        r = requests.get(url, params=params, timeout=8)
        r.raise_for_status()
        articles = r.json().get("articles", [])
        if articles:
            a = articles[0]
            return {
                "title": a.get("title") or "Related article",
                "url": a.get("url"),
                "source": (a.get("source") or {}).get("name", "News"),
            }
    except Exception as e:
        log.warning(f"⚠️ NewsAPI article fetch failed for {cve_id}: {e}")
    return None


def get_trend_score(cve_id: str):
    """Fetch trend data (NewsAPI + optional GitHub fallback)."""
    news_hits = 0
    gh_hits = 0
    exploit_boost = 0.0

    if NEWSAPI_KEY:
        try:
            url = f"https://newsapi.org/v2/everything?q={cve_id}&apiKey={NEWSAPI_KEY}"
            r = requests.get(url, timeout=8)
            r.raise_for_status()
            data = r.json()
            news_hits = data.get("totalResults", 0)
        except Exception as e:
            log.warning(f"⚠️ NewsAPI lookup failed for {cve_id}: {e}")

    try:
        gh_url = f"https://github.com/search?q={cve_id}"
        r = requests.get(gh_url, timeout=6, headers={"User-Agent": "Mozilla/5.0"})
        if "repository results" in r.text.lower():
            gh_hits = 1
    except Exception:
        pass

    news_n = math.log1p(min(news_hits, NEWS_CAP)) / math.log1p(NEWS_CAP)
    gh_n = 1.0 if gh_hits > 0 else 0.0
    trend_raw = 0.7 * news_n + 0.3 * gh_n
    trend_score = min(1.0, trend_raw + exploit_boost)

    return round(trend_score, 3), {
        "news_hits": news_hits,
        "github_hits": gh_hits,
        "exploit_boost": exploit_boost,
        "trend_raw": round(trend_raw, 3),
    }

# -------------------------------------------------------------------
# Daily Summary Generator
# -------------------------------------------------------------------
def generate_daily_summaries(top_records: list[dict]) -> dict[str, str]:
    """Use OpenAI to summarize the daily top 10 CVEs into Analyst and CISO notes."""
    if not client:
        return {"analyst": "LLM summarization skipped (no key).", "ciso": "LLM summarization skipped (no key)."}

    try:
        # Prepare structured context
        summary_input = "\n".join(
            [f"{r['cve']} ({r['vendor']} {r['product']}): {r.get('summary_analyst', '')}" for r in top_records]
        )

        analyst_prompt = (
            "You are a cybersecurity analyst for ACME Services. Write a concise 2–3 sentence daily intelligence brief "
            "summarizing key patterns, exploitation trends, and noteworthy vulnerabilities observed today.\n\n"
            f"Today's Top CVEs:\n{summary_input}"
        )

        ciso_prompt = (
            "You are a Chief Information Security Officer for ACME Services. Provide a 3 sentence executive-level summary "
            "of today's vulnerability landscape focusing on business impact, exposure of financial risk, and recommended focus areas.\n\n"
            f"Today's Top CVEs:\n{summary_input}"
        )

        analyst_resp = client.responses.create(
            model="gpt-4.1-mini",
            input=analyst_prompt,
            temperature=0.5,
        )
        ciso_resp = client.responses.create(
            model="gpt-4.1-mini",
            input=ciso_prompt,
            temperature=0.4,
        )

        analyst_text = analyst_resp.output_text.strip()
        ciso_text = ciso_resp.output_text.strip()

        log.info("🧠 Generated daily Analyst + CISO summaries via OpenAI")
        return {"analyst": analyst_text, "ciso": ciso_text}

    except Exception as e:
        log.warning(f"⚠️ Failed to generate daily summaries: {e}")
        return {"analyst": "Summary generation error.", "ciso": "Summary generation error."}


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
            cvss, vendor, product = get_cvss_vendor_product(cve)
            epss = get_epss_score(cve)
            vendor = vendor or "Unknown"
            product = product or "Unknown"
            desc = f"{vendor} {product}"

            # Exploit-DB
            if cve in exploit_cache:
                cached = exploit_cache[cve]
                if isinstance(cached, list) and len(cached) == 3:
                    exploit_found, exploit_edb_ids, exploit_urls = cached
                elif isinstance(cached, list) and len(cached) == 2:
                    exploit_found, exploit_urls = cached
                    exploit_edb_ids = []
                    for u in exploit_urls:
                        m = re.search(r"/exploits/(\d+)", u)
                        if m:
                            exploit_edb_ids.append(m.group(1))
                else:
                    exploit_found, exploit_edb_ids, exploit_urls = False, [], []
            else:
                exploit_found, exploit_edb_ids, exploit_urls = has_exploit_poc(cve)
                exploit_cache[cve] = [bool(exploit_found), exploit_edb_ids or [], exploit_urls or []]
                updated_cache = True

            # Trend
            trend_score, trend_breakdown = get_trend_score(cve)
            trend_mentions = trend_breakdown.get("news_hits", 0)

            news_article = get_article_for_cve(cve)
            if news_article:
                log.info(f"📰 {cve}: {news_article['source']} — {news_article['title'][:70]}")

            # Context + Summaries
            ctx_data = compute_context_fit(cve, vendor, product, desc, ctx)
            ctx_mult = ctx_data["fit_score"] if isinstance(ctx_data, dict) and "fit_score" in ctx_data else 1.0
            summaries = summarize_cve(cve, vendor, product, desc, ctx)
            summary_analyst = summaries.get("analyst")
            summary_ciso = summaries.get("ciso")

            # AI Context
            ai_context, ai_breakdown = compute_ai_context_score(
                vendor=vendor,
                product=product,
                description=f"{desc} {summary_analyst or ''}",
                references=[],
                cpes=[],
            )

            aura_score = compute_aura_score(
                cvss,
                epss=epss,
                kev=True,
                ctx_mult=ctx_mult,
                trend_score=trend_score,
                exploit_poc=exploit_found,
                ai_context=ai_context,
            )

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
                "aura_score": round(aura_score, 1),
                "cvss": round(cvss or 0, 1),
                "epss": round(epss or 0, 3),
                "kev": True,
                "trend_score": trend_score,
                "trend_mentions": trend_mentions,
                "trend_breakdown": trend_breakdown,
                "exploit_poc": exploit_found,
                "exploit_edb_ids": exploit_edb_ids,
                "exploit_urls": exploit_urls,
                "ai_context": round(ai_context, 3),
                "ai_breakdown": ai_breakdown,
                "vendor": vendor,
                "product": product,
                "summary_analyst": summary_analyst,
                "summary_ciso": summary_ciso,
                "description": summary_analyst,
                "news_article": news_article,
                "score_breakdown": score_breakdown,
            }

            records.append(record)
            log.info(
                f"✅ {cve} | CVSS {cvss:.1f} | EPSS {epss:.3f} | Trend {trend_mentions} hits | "
                f"Exploit: {exploit_found} | AI {ai_context:.2f} | AURA {aura_score:.1f}"
            )

        except Exception as e:
            log.warning(f"⚠️ Failed to process {cve}: {e}")

    if updated_cache:
        save_exploit_cache(exploit_cache)
        log.info(f"💾 Updated Exploit-DB cache with {len(exploit_cache)} entries")

    records.sort(key=lambda x: x.get("aura_score", 0), reverse=True)
    top_records = records[:10]

    if records:
        min_score = round(min(r["aura_score"] for r in records), 1)
        max_score = round(max(r["aura_score"] for r in records), 1)
        log.info(f"📊 AURA Score Range: {min_score} – {max_score}")
    log.info(f"🏆 Selected Top {len(top_records)} CVEs by AURA score")

    # 🧠 Generate daily Analyst/CISO summaries via OpenAI
    daily_summaries = generate_daily_summaries(top_records)

    # ✅ ADD REAL UTC TIMESTAMP FIELD
    last_run_utc = dt.datetime.now(dt.timezone.utc).isoformat()
    log.info(f"🕒 AURA data generated at {last_run_utc}")

    output_data = {
        "last_run": last_run_utc,  # ✅ used by frontend
        "generated": dt.datetime.utcnow().isoformat(),
        "daily_analyst_summary": daily_summaries["analyst"],
        "daily_ciso_summary": daily_summaries["ciso"],
        "cves": top_records,
    }

    os.makedirs(os.path.dirname(OUTPUT_SCORES), exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_MASTER), exist_ok=True)

    today = dt.date.today().isoformat()
    try:
        with open(OUTPUT_SCORES, "w") as f:
            json.dump(output_data, f, indent=2)
        with open(OUTPUT_MASTER, "w") as f:
            json.dump({"date": today, "records": records}, f, indent=2)
        with open(os.path.join(HISTORY_DIR, f"{today}.json"), "w") as f:
            json.dump(records, f, indent=2)
    except Exception as e:
        log.error(f"Failed to write output files: {e}")
        return

    log.info(f"✅ Saved Top {len(top_records)} CVEs + daily summaries to {OUTPUT_SCORES}")
    log.info(f"📅 History snapshot written to {HISTORY_DIR}/{today}.json")


if __name__ == "__main__":
    main()
