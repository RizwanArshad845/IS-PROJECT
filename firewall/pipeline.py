"""The firewall: normalizer -> rules -> ML -> policy -> log.

    from firewall.pipeline import scan
    result = scan(text, source="email:3", user_task="Summarize my inbox")
    result.decision   # ALLOW | SANITIZE | BLOCK
    result.safe_text  # what the agent is allowed to see
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field

from . import policy, rules
from .logger import log_event
from .normalizer import normalize


@dataclass
class ScanResult:
    decision: str
    score: float
    rule_score: float
    ml_score: float | None
    attack_types: list[str]
    reasons: list[str]
    safe_text: str
    source: str
    latency_ms: float
    findings: list[dict] = field(default_factory=list)
    matches: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _ml_score(text: str) -> float | None:
    """Phase 5 hook: returns None until a trained model exists in models/."""
    try:
        from . import ml_model
    except ImportError:
        return None
    return ml_model.score(text)


def scan(text: str, source: str = "unknown", user_task: str = "", log: bool = True, use_ml: bool = True) -> ScanResult:
    t0 = time.perf_counter()
    norm = normalize(text)
    rr = rules.check(norm)
    ml = _ml_score(norm.text) if use_ml else None
    d = policy.decide(rr, ml, user_task)

    if d.decision == policy.BLOCK:
        safe = f"[FIREWALL] Content from {source} was blocked because it contains a likely prompt-injection attack."
    elif d.decision == policy.SANITIZE:
        safe = policy.sanitize(norm.text, [m.span for m in rr.matches if m.span], source)
    else:
        safe = norm.text

    result = ScanResult(
        decision=d.decision, score=d.score, rule_score=rr.score, ml_score=ml,
        attack_types=rr.attack_types, reasons=d.reasons, safe_text=safe, source=source,
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
        findings=[asdict(f) for f in norm.findings],
        matches=[asdict(m) for m in rr.matches],
    )
    if log:
        log_event({"type": "scan", "user_task": user_task, "original": text[:2000],
                   **{k: v for k, v in result.to_dict().items() if k != "matches"}})
    return result
