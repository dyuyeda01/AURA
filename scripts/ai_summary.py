import os, logging
from openai import OpenAI

log = logging.getLogger(__name__)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
oai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

def summarize_cve(cve_id: str, vendor: str, product: str, description: str, ctx: dict | None = None) -> dict:
    """
    Generate two AI summaries for the CVE:
      - 'analyst': concise technical insight
      - 'ciso': executive/business impact view
    Returns a dict: {"analyst": str, "ciso": str}
    """
    if oai_client is None:
        base = f"{cve_id} affects {vendor} {product}."
        return {"analyst": base, "ciso": base}

    ctx_desc = ""
    if ctx:
        env = ", ".join(ctx.get("cloud", []) + ctx.get("os", []))
        ctx_desc = f"Environment: {ctx.get('sector','')} sector, {ctx.get('risk_tolerance','')} tolerance, {env}"

    try:
        # --- Analyst prompt (technical summary)
        resp_analyst = oai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity analyst summarizing technical vulnerabilities. "
                        "Write one clear, factual sentence focusing on exploit mechanics, "
                        "affected component, and impact severity."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Summarize {cve_id} affecting {vendor} {product}. "
                        f"Description: {description}. {ctx_desc}"
                    ),
                },
            ],
        )
        analyst_summary = resp_analyst.choices[0].message.content.strip()

        # --- CISO prompt (executive/business summary)
        resp_ciso = oai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a Chief Information Security Officer (CISO) summarizing risk for executives. "
                        "Write one concise, non-technical sentence highlighting business impact, "
                        "exposure risk, and urgency of mitigation."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Summarize {cve_id} affecting {vendor} {product}. "
                        f"Description: {description}. {ctx_desc}"
                    ),
                },
            ],
        )
        ciso_summary = resp_ciso.choices[0].message.content.strip()

        return {"analyst": analyst_summary, "ciso": ciso_summary}

    except Exception as e:
        log.warning(f"⚠️ AI summary failed for {cve_id}: {e}")
        base = f"{cve_id}: Apply mitigations promptly."
        return {"analyst": base, "ciso": base}
