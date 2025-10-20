# scripts/trend.py
"""
Trend scoring module — queries NewsAPI for CVE mentions
and optionally falls back to lightweight GitHub scraping.
"""

import os, math, logging, requests

log = logging.getLogger(__name__)
NEWSAPI_KEY = os.getenv("NEWSAPI_KEY")

# cap for normalization
NEWS_CAP = 50.0  # 50+ mentions counts as full saturation


def get_trend_score(cve_id: str):
    """Return (score_0_to_1, breakdown_dict)."""

    news_hits = 0
    gh_hits = 0
    exploit_boost = 0.0

    # -----------------------------
    # Try NewsAPI first
    # -----------------------------
    if NEWSAPI_KEY:
        try:
            url = f"https://newsapi.org/v2/everything?q={cve_id}&apiKey={NEWSAPI_KEY}"
            r = requests.get(url, timeout=8)
            r.raise_for_status()
            data = r.json()
            news_hits = data.get("totalResults", 0)
        except Exception as e:
            log.warning(f"⚠️ NewsAPI lookup failed for {cve_id}: {e}")

    # -----------------------------
    # Fallback — GitHub mentions (optional simple HTML scrape)
    # -----------------------------
    try:
        gh_url = f"https://github.com/search?q={cve_id}"
        r = requests.get(gh_url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        if "repository results" in r.text.lower():
            gh_hits = 1  # coarse indicator
    except Exception:
        pass

    # -----------------------------
    # Compute normalized scores
    # -----------------------------
    news_n = math.log1p(min(news_hits, NEWS_CAP)) / math.log1p(NEWS_CAP)
    gh_n = 1.0 if gh_hits > 0 else 0.0

    trend_raw = 0.7 * news_n + 0.3 * gh_n
    trend_score = min(1.0, trend_raw + exploit_boost)

    breakdown = {
        "news_hits": news_hits,
        "github_hits": gh_hits,
        "exploit_boost": exploit_boost,
        "trend_raw": round(trend_raw, 3)
    }

    return round(trend_score, 3), breakdown
