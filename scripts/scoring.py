# scripts/scoring.py
def compute_aura_score(
    cvss: float = 0.0,
    epss: float = 0.0,
    kev: bool = False,
    ctx_mult=None,
    trend_score: float = 0.0,
    exploit_poc: bool = False,
) -> float:
    """Compute unified AURA score, supporting dict or float context."""
    weights = {
        "cvss": 0.4,
        "epss": 0.2,
        "kev": 0.2,
        "exploit": 0.1,
        "trend": 0.05,
        "ai": 0.05,
    }

    # Extract numeric multiplier if dict provided
    if isinstance(ctx_mult, dict):
        ctx_mult = ctx_mult.get("fit_score", 1.0)
    elif not isinstance(ctx_mult, (int, float)):
        ctx_mult = 1.0

    cvss_n = min(max(cvss / 10, 0), 1)
    epss_n = min(max(epss, 0), 1)
    kev_n = 1.0 if kev else 0.0
    exploit_n = 1.0 if exploit_poc else 0.0
    trend_n = min(max(trend_score, 0), 1)

    score = (
        cvss_n * weights["cvss"]
        + epss_n * weights["epss"]
        + kev_n * weights["kev"]
        + exploit_n * weights["exploit"]
        + trend_n * weights["trend"]
    )

    score *= ctx_mult
    return round(score * 100, 1)
