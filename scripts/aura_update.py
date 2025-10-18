# scripts/aura_update.py
import os, json, datetime, math, random
from collectors.kev_collector import get_kev_data
from collectors.epss_collector import get_epss_score
from collectors.nvd_collector import get_cvss
from collectors.exploitdb_collector import has_public_poc

# In the live version, read from env inside your summarizer:
# import openai; openai.api_key = os.getenv("OPENAI_API_KEY")

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
PUBLIC_DATA = os.path.join(BASE_DIR, "public", "data", "aura_scores.json")
HISTORY_DIR = os.path.join(BASE_DIR, "data", "history")
MASTER_FILE = os.path.join(BASE_DIR, "data", "aura_master.json")

def normalize(v, min_v, max_v):
    if max_v == min_v:
        return 0.0
    return max(0.0, min(1.0, (v - min_v) / (max_v - min_v)))

def compute_aura_score(cvss, epss, kev, exploit, trend, ai_context):
    # All components in [0..1]
    cvss_n = cvss / 10.0
    epss_n = max(0.0, min(1.0, epss))
    kev_n = 1.0 if kev else 0.0
    exploit_n = 1.0 if exploit else 0.0
    trend_n = min(1.0, trend / 20.0)  # cap at 20 mentions
    ai_n = max(0.0, min(1.0, ai_context))

    # Simple weighted fusion (tweak later)
    score = (
        0.30 * cvss_n +
        0.20 * epss_n +
        0.20 * kev_n +
        0.15 * exploit_n +
        0.10 * trend_n +
        0.05 * ai_n
    ) * 100.0

    return int(round(min(100, score)))

def fake_ai_summary(cve, vendor, product, score, kev, exploit, trend):
    # Placeholder LLM summary. Replace with OpenAI call later.
    risk = "Critical" if score >= 90 else "High" if score >= 80 else "Moderate"
    kev_txt = "confirmed exploited (KEV)" if kev else "not in KEV"
    poc_txt = "public PoC available" if exploit else "no public PoC observed"
    trend_txt = f"trend mentions: {trend}"
    return (f"{cve} — {risk}. Targeting {vendor} {product}; {kev_txt}, {poc_txt}, {trend_txt}. "
            f"Prioritize patching and restrict internet-facing access where possible.")

def ensure_master():
    if not os.path.exists(MASTER_FILE):
        with open(MASTER_FILE, "w") as f:
            json.dump({}, f, indent=2)

def update_master(records, today):
    with open(MASTER_FILE, "r") as f:
        master = json.load(f)
    for r in records:
        cve = r["cve"]
        if cve not in master:
            master[cve] = {
                "vendor": r.get("vendor"),
                "product": r.get("product"),
                "history": []
            }
        master[cve]["latest_score"] = r["aura_score"]
        master[cve]["summary"] = r["summary"]
        # append time series point
        master[cve]["history"].append({
            "date": today,
            "score": r["aura_score"]
        })
    with open(MASTER_FILE, "w") as f:
        json.dump(master, f, indent=2)

def write_history(today, records):
    os.makedirs(HISTORY_DIR, exist_ok=True)
    history_path = os.path.join(HISTORY_DIR, f"{today}.json")
    with open(history_path, "w") as f:
        json.dump(records, f, indent=2)
    return history_path

def prune_history(days=365):
    cutoff = datetime.date.today() - datetime.timedelta(days=days)
    for fname in os.listdir(HISTORY_DIR):
        if not fname.endswith(".json"):
            continue
        try:
            d = datetime.datetime.strptime(fname.replace(".json",""), "%Y-%m-%d").date()
        except ValueError:
            continue
        if d < cutoff:
            os.remove(os.path.join(HISTORY_DIR, fname))

def main():
    today = datetime.date.today().isoformat()

    kev_items = get_kev_data()
    records = []
    # Simulate "trend mentions" locally
    rng = random.Random(42)

    for item in kev_items:
        cve = item["cve"]
        vendor = item.get("vendor","Unknown")
        product = item.get("product","Unknown")
        cvss = get_cvss(cve)
        epss = get_epss_score(cve)
        kev = bool(item.get("kev", False))
        exploit = has_public_poc(cve)
        trend = rng.randint(0, 18)  # placeholder trend mentions
        ai_context = 0.8 if "web" in item.get("description","").lower() else 0.6

        aura_score = compute_aura_score(cvss, epss, kev, exploit, trend, ai_context)
        summary = fake_ai_summary(cve, vendor, product, aura_score, kev, exploit, trend)

        records.append({
            "date": today,
            "cve": cve,
            "vendor": vendor,
            "product": product,
            "cvss": cvss,
            "epss": epss,
            "kev": kev,
            "exploit_poc": exploit,
            "trend_mentions": trend,
            "ai_context": ai_context,
            "aura_score": aura_score,
            "summary": summary,
            "score_breakdown": {
                "cvss_weight": 0.30, "cvss_norm": cvss/10.0,
                "epss_weight": 0.20, "epss_norm": epss,
                "kev_weight": 0.20, "kev_norm": 1.0 if kev else 0.0,
                "exploit_weight": 0.15, "exploit_norm": 1.0 if exploit else 0.0,
                "trend_weight": 0.10, "trend_norm": min(1.0, trend/20.0),
                "ai_weight": 0.05, "ai_norm": ai_context
            }
        })

    # Sort and keep top 10
    records.sort(key=lambda r: r["aura_score"], reverse=True)
    top10 = records[:10]

    # Write latest feed
    os.makedirs(os.path.dirname(PUBLIC_DATA), exist_ok=True)
    with open(PUBLIC_DATA, "w") as f:
        json.dump(top10, f, indent=2)

    # Write history + master
    ensure_master()
    write_history(today, top10)
    update_master(top10, today)

    # Prune > 365 days
    prune_history(365)

    print(f"Wrote {len(top10)} records to {PUBLIC_DATA}")

if __name__ == "__main__":
    main()
