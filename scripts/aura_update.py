#!/usr/bin/env python3
"""
AURA update script — KEV-driven enrichment pipeline.
Fetches the latest Known Exploited Vulnerabilities (CISA),
retrieves their NVD details (CVSS, descriptions, metrics),
generates AI summaries, and saves Top 10 ranked by severity.

Environment variables:
  - NVD_API_KEY: your NVD API key
  - OPENAI_API_KEY: your OpenAI API key (optional)
"""

import os
import json
import datetime
import logging
import requests
from openai import OpenAI

# --- Configuration ---
MAX_CVES = 10
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_SCORES = "public/data/aura_scores.json"
OUTPUT_MASTER = "data/aura_master.json"
HISTORY_DIR = "data/history"
os.makedirs(HISTORY_DIR, exist_ok=True)

# --- Logging ---
logging.basicConfig(
    format="[%(asctime)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO
)
log = logging.getLogger()

# --- API Keys ---
NVD_API_KEY = os.getenv("NVD_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

if not NVD_API_KEY:
    log.warning("⚠️ Missing NVD_API_KEY — will still run, but details may fail.")
if not OPENAI_API_KEY:
    log.warning("⚠️ Missing OPENAI_API_KEY — AI summaries disabled.")

# --- Step 1: Fetch KEV list ---
def fetch_kev_list(limit=MAX_CVES):
    log.info(f"📡 Fetching KEV feed from {KEV_FEED}")
    r = requests.get(KEV_FEED, timeout=30)
    r.raise_for_status()
    data = r.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        log.error("❌ No vulnerabilities found in KEV feed.")
        return []
    # Sort newest first
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    cves = [v["cveID"] for v in vulns[:limit]]
    log.info(f"✅ Retrieved {len(cves)} KEV CVEs: {', '.join(cves)}")
    return cves

# --- Step 2: Get CVSS from NVD ---
def fetch_nvd_details(cve):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        r = requests.get(f"{NVD_URL}?cveId={cve}", headers=headers, timeout=30)
        if r.status_code == 403:
            log.warning(f"[WARN] NVD denied access for {cve} (invalid or missing API key)")
            return {"cve": cve, "score": 0.0, "desc": "Access denied."}
        r.raise_for_status()
        data = r.json()
        items = data.get("vulnerabilities", [])
        if not items:
            return {"cve": cve, "score": 0.0, "desc": "No NVD data found."}
        cve_item = items[0]["cve"]
        desc = cve_item["descriptions"][0]["value"]
        metrics = cve_item.get("metrics", {})
        cvss = 0.0
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        return {"cve": cve, "score": cvss, "desc": desc}
    except requests.exceptions.RequestException as e:
        log.error(f"❌ Failed to fetch NVD details for {cve}: {e}")
        return {"cve": cve, "score": 0.0, "desc": "Error fetching NVD data"}

# --- Step 3: Generate AI Summary ---
def generate_summary(cve_id, description, score):
    if not client:
        return f"{cve_id} (CVSS {score}): {description[:150]}..."
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst summarizing CVEs."},
                {"role": "user", "content": f"Summarize {cve_id} in one concise sentence for a vulnerability analyst. Include why it matters."}
            ],
            max_tokens=100
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        log.warning(f"⚠️ OpenAI summary failed for {cve_id}: {e}")
        return f"{cve_id}: {description[:120]}..."

# --- Step 4: Main pipeline ---
def main():
    log.info("🚀 Starting AURA update run")
    today = datetime.date.today().isoformat()

    cve_list = fetch_kev_list()
    if not cve_list:
        log.warning("⚠️ No CVEs retrieved; exiting.")
        return

    records = []
    for cve in cve_list:
        details = fetch_nvd_details(cve)
        summary = generate_summary(cve, details["desc"], details["score"])
        records.append({
            "cve": cve,
            "cvss": details["score"],
            "description": details["desc"],
            "summary": summary
        })

    # Sort Top 10 by CVSS
    records.sort(key=lambda x: x["cvss"], reverse=True)

    # Save outputs
    os.makedirs(os.path.dirname(OUTPUT_SCORES), exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_MASTER), exist_ok=True)

    with open(OUTPUT_SCORES, "w") as f:
        json.dump(records, f, indent=2)
    with open(OUTPUT_MASTER, "w") as f:
        json.dump({"date": today, "records": records}, f, indent=2)
    with open(f"{HISTORY_DIR}/{today}.json", "w") as f:
        json.dump(records, f, indent=2)

    log.info(f"✅ Saved Top {len(records)} CVEs to {OUTPUT_SCORES}")
    log.info(f"📅 History snapshot written to {HISTORY_DIR}/{today}.json")

# --- Entry ---
if __name__ == "__main__":
    main()
