# AURA — AI Unified Risk Assessment

**AURA** is a free, serverless vulnerability intelligence prototype that fuses public data (KEV, NVD/CVSS, EPSS, exploit evidence, trend signals) into a single, **explainable risk score** and a daily **Top 10** feed.

- ✅ Hosted on GitHub Pages (static frontend)
- ✅ Automated with GitHub Actions (daily)
- ✅ One-year JSON history with auto-prune
- ✅ Elegant UI (dark cyber theme, Tailwind)
- ✅ Trends page (Chart.js) and resources (Mermaid diagram)
- 🧠 Placeholder collectors now; swap in live data later
- 💸 Cost: ~$0.50/mo for OpenAI if you enable real summaries

## Quick Start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt  # (optional in future when adding live requests/openai)
python scripts/aura_update.py
# Open public/index.html in your browser (or enable GitHub Pages)
```

## Structure
```
scripts/           # collectors + orchestrator
data/              # master + history snapshots
public/            # static site (Top 10, trends, resources)
.github/workflows/ # daily automation
```

## API Keys
Do **not** commit keys. Set environment variable locally:
```bash
export OPENAI_API_KEY="sk-..."
```
In GitHub/GitLab, store it as a repo secret/variable.

## Swap to Live Data
Edit the collectors in `scripts/collectors/` to call KEV/NVD/EPSS/Exploit-DB APIs.
Update `scripts/aura_update.py` to generate OpenAI summaries (replace `fake_ai_summary`).

## License
MIT
