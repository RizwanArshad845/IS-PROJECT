"""Phase 5 - ML model loader used by pipeline.scan().

score(text) -> probability (0..1) that the text is a prompt injection,
or None if no trained model exists yet (the firewall then runs rules-only).
"""
from __future__ import annotations

from functools import lru_cache

from .config import ROOT

MODEL_PATH = ROOT / "models" / "baseline.joblib"


@lru_cache(maxsize=1)
def _model():
    if not MODEL_PATH.exists():
        return None
    import joblib
    return joblib.load(MODEL_PATH)


def score(text: str) -> float | None:
    m = _model()
    if m is None:
        return None
    return round(float(m.predict_proba([text])[0][1]), 4)
