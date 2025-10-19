import os, yaml, logging
log = logging.getLogger(__name__)

def load_context() -> dict:
    """Load context.yaml if available."""
    path = "context.yaml"
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            ctx = yaml.safe_load(f) or {}
        log.info(f"📁 Loaded context from {path}")
        return ctx
    except Exception as e:
        log.warning(f"⚠️ Failed to load context.yaml: {e}")
        return {}

def compute_context_fit(cve_id: str, vendor: str, product: str, description: str, ctx: dict) -> dict:
    """Adjust weight multipliers (0.8–1.3x) based on org context."""
    if not ctx:
        return {k: 1.0 for k in ["cvss", "epss", "kev", "exploit", "trend", "ai"]}

    sector = (ctx.get("sector") or "").lower()
    os_list = [x.lower() for x in ctx.get("os", [])]
    cloud = [x.lower() for x in ctx.get("cloud", [])]
    risk_tol = (ctx.get("risk_tolerance") or "medium").lower()
    internet_exposed = bool(ctx.get("internet_exposed", False))

    mult = {k: 1.0 for k in ["cvss", "epss", "kev", "exploit", "trend", "ai"]}

    if any(s in sector for s in ["finance", "health", "government"]):
        mult["cvss"] += 0.1
    if internet_exposed:
        mult["kev"] += 0.1
    if risk_tol == "low":
        for k in mult: mult[k] += 0.05
    elif risk_tol == "high":
        for k in mult: mult[k] -= 0.05

    for k in mult:
        mult[k] = round(max(0.8, min(1.3, mult[k])), 2)
    return mult
