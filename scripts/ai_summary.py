import os, logging
from openai import OpenAI

log = logging.getLogger(__name__)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
oai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

def summarize_cve(cve_id: str, vendor: str, product: str, description: str, ctx: dict | None = None) -> str:
    """Generate an AI summary for the CVE."""
    if oai_client is None:
        return f"{cve_id} affects {vendor} {product}."

    ctx_desc = ""
    if ctx:
        env = ", ".join(ctx.get("cloud", []) + ctx.get("os", []))
        ctx_desc = f"Environment: {ctx.get('sector','')} sector, {ctx.get('risk_tolerance','')} tolerance, {env}"

    prompt = f"Summarize {cve_id} for {vendor} {product}. {ctx_desc}"
    try:
        resp = oai_client.chat.completions.create(
            model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}]
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        log.warning(f"⚠️ AI summary failed for {cve_id}: {e}")
        return f"{cve_id}: Apply mitigations promptly."
