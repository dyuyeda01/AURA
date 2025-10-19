# scripts/scoring.py
"""Compute AURA composite risk score."""

def compute_aura_score(cvss: float, epss: float = 0.0, kev: bool = False, ctx_mult: dict | None = None) -> float:
    """
    Compute weighted AURA score (0–100) with optional context scaling.
    EPSS values (0–1) are scaled to 0–100 range before weighting.
    """
    if ctx_mult is None:
        ctx_mult = {k: 1.0 for k in ["cvss", "epss", "kev", "exploit", "trend", "ai"]}

    W_CVSS, W_EPSS, W_KEV, W_EXPLOIT, W_TREND, W_AI = 0.40, 0.20, 0.20, 0.10, 0.05, 0.05

    cvss_0_100 = min(100.0, (cvss or 0.0) * 10.0)
    epss_0_100 = min(100.0, (epss or 0.0) * 100.0)

    score = (
        cvss_0_100 * W_CVSS * ctx_mult["cvss"]
        + epss_0_100 * W_EPSS * ctx_mult["epss"]
        + (100 if kev else 0) * W_KEV * ctx_mult["kev"]
        + 0 * W_EXPLOIT * ctx_mult["exploit"]
        + 0 * W_TREND * ctx_mult["trend"]
        + 0 * W_AI * ctx_mult["ai"]
    )
    return round(score, 1)
