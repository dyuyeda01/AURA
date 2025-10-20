# scripts/ai_context.py
"""
AI Context scoring: detects mentions of AI/ML vendors, frameworks, model names,
tooling, and infra in CVE metadata to produce a 0–1 score plus matched keywords.

Return: (score: float in [0,1], breakdown: dict with matched keywords by tier)
"""

from __future__ import annotations
import re
from typing import Iterable, Tuple, Dict, List, Optional

# Curated AI supply-chain keywords (expand anytime)
AI_KEYWORDS = {
    "high": [
        # Core frameworks / runtimes / model families
        "tensorflow", "pytorch", "jax", "onnx", "openvino", "triton inference",
        "transformers", "langchain", "llama", "gpt", "mistral", "sdxl",
        # Commercial APIs / platforms
        "openai", "anthropic", "google vertex ai", "vertex ai", "amazon bedrock", "bedrock", "cohere",
        # Model serving / orchestration
        "ray serve", "ray", "bentoml", "seldon", "mlflow", "kubeflow", "triton server",
        # Vector DBs commonly used in RAG
        "pinecone", "weaviate", "milvus", "qdrant", "chromadb",
        # Popular OSS toolchains
        "ollama", "vllm", "ludwig", "deepspeed", "accelerate", "vectra",
        # Notable vendors
        "hugging face", "huggingface", "stability ai",
    ],
    "medium": [
        "scikit-learn", "xgboost", "lightgbm", "catboost",
        "airflow", "feast", "dvc", "weights & biases", "wandb",
        "modal", "replicate",
        "autogen", "crew ai", "crewai",
    ],
    "low": [
        "notebook", "jupyter", "gpu", "cuda", "tensorrt", "nccL", "rocM",
        "rag", "embedding", "vector search", "prompt", "llm", "agent",
    ],
}

# Pre-compile regex for efficiency
def _compile_terms(terms: Iterable[str]) -> List[re.Pattern]:
    patterns: List[re.Pattern] = []
    for t in terms:
        # allow word-ish boundary or substring match with spaces
        if " " in t:
            pat = re.compile(re.escape(t), re.IGNORECASE)
        else:
            pat = re.compile(rf"\b{re.escape(t)}\b", re.IGNORECASE)
        patterns.append(pat)
    return patterns

PATTERNS = {
    level: _compile_terms(terms) for level, terms in AI_KEYWORDS.items()
}

def compute_ai_context_score(
    vendor: str = "",
    product: str = "",
    description: str = "",
    references: Optional[List[str]] = None,
    cpes: Optional[List[str]] = None,
) -> Tuple[float, Dict]:
    """
    Produce an AI-context score in [0,1] and a breakdown of matched keywords.
    Heuristic weighting:
      - high matches weigh the most, then medium, then low
      - multiple matches increase score but cap at 1.0
    """
    refs = " ".join(references or [])
    cpe_str = " ".join(cpes or [])
    corpus = " ".join([vendor, product, description, refs, cpe_str]).lower()

    matched = {"high": [], "medium": [], "low": []}

    # find unique matches preserving input order by using a set
    seen = set()

    for level in ["high", "medium", "low"]:
        for pat in PATTERNS[level]:
            for m in pat.finditer(corpus):
                term = m.group(0).lower()
                if term not in seen:
                    seen.add(term)
                    matched[level].append(term)

    # Scoring heuristic
    high_hits = len(matched["high"])
    med_hits  = len(matched["medium"])
    low_hits  = len(matched["low"])

    # weights — tune as desired
    score = min(
        1.0,
        high_hits * 0.5 + med_hits * 0.25 + low_hits * 0.1
    )

    breakdown = {
        "score": round(score, 3),
        "matched": matched,
        "counts": {
            "high": high_hits, "medium": med_hits, "low": low_hits
        }
    }
    return score, breakdown
