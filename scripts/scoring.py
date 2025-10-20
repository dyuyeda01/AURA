# scripts/scoring.py
"""Compute AURA composite risk score with AI Context support."""

def compute_aura_score(
    cvss: float = 0.0,
    epss: float = 0.0,
    kev: bool = False,
    ctx_mult: float = 1.0,
    trend_score: float = 0.0,
    exploit_poc: bool = False,
    ai_context: float = 0.0,
) -> float:
    """
    Compute the unified AURA score (0–100) using weighted components:
    CVSS, EPSS, KEV, Exploit-DB, Trend, and AI Context.
    """
    weights = {
        "cvss": 0.4,
        "epss": 0.2,
        "kev": 0.2,
        "exploit": 0.1,
        "trend": 0.05,
        "ai": 0.05,
    }

    # Normalize input ranges
    cvss_n = min(max(cvss / 10, 0), 1)
    epss_n = min(max(epss, 0), 1)
    kev_n = 1.0 if kev else 0.0
    exploit_n = 1.0 if exploit_poc else 0.0
    trend_n = min(max(trend_score, 0), 1)
    ai_n = min(max(ai_context, 0), 1)

    # Weighted score
    score = (
        cvss_n * weights["cvss"]
        + epss_n * weights["epss"]
        + kev_n * weights["kev"]
        + exploit_n * weights["exploit"]
        + trend_n * weights["trend"]
        + ai_n * weights["ai"]
    )

    # Apply context multiplier
    score *= ctx_mult

    return round(score * 100, 1)
