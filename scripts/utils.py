# scripts/utils.py
from __future__ import annotations
from dataclasses import dataclass

@dataclass
class ScoreBreakdown:
    cvss: float
    epss: float
    kev: bool
    exploit_poc: bool
    trend: int
    ai_context: float
    aura_score: int
