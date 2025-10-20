# 🛰️ AURA — AI Unified Risk Assessment

**AURA** is a **serverless vulnerability intelligence prototype** that aggregates and analyzes open-source risk data to deliver a single **explainable risk score** and a daily **Top 10 Threat Feed**.  
It combines data from **CISA KEV**, **NVD/CVSS**, **EPSS**, and exploit repositories to identify and contextualize emerging vulnerabilities with AI-powered summaries.

> Designed for security engineers, threat hunters, and analysts who want automated, explainable, and continuously updated vulnerability intelligence — without standing up infrastructure.

---

## 🔧 Key Features

- **Serverless & Automated** — Runs nightly via GitHub Actions; no servers or cron jobs to maintain  
- **Live Data Fusion** — Integrates KEV, NVD, CVSS, EPSS, and exploit evidence  
- **Explainable AI Scoring** — Generates plain-language insights with OpenAI (optional)  
- **Versioned History** — Maintains a rolling one-year JSON archive with auto-prune  
- **Modern UI** — Responsive Tailwind design with dark cyber aesthetic  
- **Visual Intelligence** — Chart.js for trend analytics and Mermaid for system architecture diagrams  
- **Cost-Effective** — ~$0.50/mo for OpenAI summaries (fully optional)

---

AURA was built to demonstrate how AI and open data can converge to produce actionable, transparent risk intelligence.
It’s an evolving experiment in AI-assisted cyber threat awareness, automation, and explainable decision support — designed to inspire more open, automated security ecosystems.