"""Phase 7 - Evasion test: take attacks the firewall catches, rewrite them to dodge it,
and measure how many are still caught. Failures are reported, not hidden.

    python -m eval.evasion
"""
from __future__ import annotations

import base64
import codecs
import json
import random
import re

import pandas as pd

from firewall.config import ROOT
from firewall.pipeline import scan

SEED = 7
N = 150
OUT = ROOT / "report" / "evasion.json"

CYR = str.maketrans({"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і"})
LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})
SYNONYMS = {r"\bignore\b": "set aside", r"\bdisregard\b": "pay no attention to", r"\bprevious\b": "earlier",
            r"\binstructions\b": "guidance", r"\bforget\b": "drop", r"\brules\b": "policies",
            r"\bsend\b": "pass along", r"\bforward\b": "relay", r"\bpassword\b": "passphrase"}
HOST = ("Hi team,\n\nThanks for joining yesterday's planning call. The slides are on the shared drive "
        "and the budget sheet was updated with the new vendor quotes. {X}\n\nWe will review the timeline "
        "again on Thursday, so please add comments before then. Lunch will be provided.\n\nBest,\nSara")


def _zero_width(t):
    return "​".join(t)


def _split(t):
    words = t.split()
    h = len(words) // 2
    return HOST.replace("{X}", " ".join(words[:h])) + "\n\nP.S. " + " ".join(words[h:])


TRANSFORMS = {
    "original":            lambda t: t,
    "base64":              lambda t: "Reference: " + base64.b64encode(t.encode()).decode(),
    "rot13":               lambda t: codecs.encode(t, "rot13"),
    "zero_width":          _zero_width,
    "homoglyph":           lambda t: t.translate(CYR),
    "hidden_html":         lambda t: f"<p>Welcome to our store.</p><div style='display:none'>{t}</div>",
    "embedded_in_email":   lambda t: HOST.replace("{X}", t),
    "split_in_two":        _split,
    "leetspeak":           lambda t: t.translate(LEET),
    "synonyms":            lambda t: _syn(t),
    "letter_spacing":      lambda t: " ".join(t),
}


def _syn(t):
    for k, v in SYNONYMS.items():
        t = re.sub(k, v, t, flags=re.I)
    return t


def main() -> None:
    df = pd.read_csv(ROOT / "data" / "splits" / "test.csv", keep_default_na=False)
    pool = df[(df.label == 1) & (df.source != "embedded") & (df.text.str.len().between(20, 400))]
    pool = pool.sample(frac=1, random_state=SEED).text.tolist()

    # only keep attacks the firewall catches in their original form, so we measure the effect of the rewrite
    caught = [t for t in pool if scan(t, log=False).decision != "ALLOW"][:N]
    results = {}
    examples = {}
    for name, fn in TRANSFORMS.items():
        flags = []
        for t in caught:
            r = scan(fn(t), log=False)
            flags.append(r.decision != "ALLOW")
            if not flags[-1] and name not in examples:
                examples[name] = fn(t)[:200]
        results[name] = round(sum(flags) / len(flags), 3)

    OUT.write_text(json.dumps({"n_attacks": len(caught), "catch_rate": results, "missed_examples": examples},
                              indent=2, ensure_ascii=False))
    print(f"## Evasion test ({len(caught)} attacks that are caught in original form)\n")
    print("| Rewrite | Still caught |\n|---|---|")
    for k, v in results.items():
        print(f"| {k} | {v:.0%} |")


if __name__ == "__main__":
    main()
