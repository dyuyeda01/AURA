def compute_aura_score(cvss: float, kev: bool, ctx_mult: dict) -> float:
    """Weighted AURA score (0–100)."""
    W_CVSS, W_EPSS, W_KEV, W_EXPLOIT, W_TREND, W_AI = 0.40, 0.20, 0.20, 0.10, 0.05, 0.05
    cvss_0_100 = min(100.0, cvss * 10.0)
    score = (
        cvss_0_100 * W_CVSS * ctx_mult["cvss"]
        + 0 * W_EPSS * ctx_mult["epss"]
        + (100 if kev else 0) * W_KEV * ctx_mult["kev"]
    )
    return round(score, 1)
