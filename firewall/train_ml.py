"""Phase 5 - Train the baseline ML model (TF-IDF + Logistic Regression).

    python -m data.build_dataset     # once, creates data/splits/*.csv
    python -m firewall.train_ml      # trains, picks C on the validation set, saves models/baseline.joblib

The model sees text AFTER the normalizer, the same text the rules see,
so base64 / hidden HTML / homoglyph tricks are already undone.
"""
from __future__ import annotations

import json
import time

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.pipeline import FeatureUnion, Pipeline

from .config import ROOT
from .ml_model import MODEL_PATH
from .normalizer import normalize

SPLITS = ROOT / "data" / "splits"


def load(name: str) -> tuple[list[str], list[int]]:
    df = pd.read_csv(SPLITS / f"{name}.csv", keep_default_na=False)
    return [normalize(t).text for t in df.text], df.label.astype(int).tolist()


def build(C: float) -> Pipeline:
    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=50_000, sublinear_tf=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=100_000, sublinear_tf=True)),
    ])
    return Pipeline([("tfidf", features),
                     ("clf", LogisticRegression(C=C, class_weight="balanced", max_iter=3000))])


def report(y, pred) -> dict:
    neg = [p for t, p in zip(y, pred) if t == 0]
    return {"precision": round(float(precision_score(y, pred)), 4), "recall": round(float(recall_score(y, pred)), 4),
            "f1": round(float(f1_score(y, pred)), 4), "false_alarm_rate": round(float(sum(neg)) / max(len(neg), 1), 4)}


def main() -> None:
    t0 = time.time()
    Xtr, ytr = load("train")
    Xva, yva = load("val")
    print(f"loaded {len(Xtr)} train / {len(Xva)} val in {time.time() - t0:.1f}s")

    best = None
    for C in (0.5, 1, 2, 4, 8):
        m = build(C).fit(Xtr, ytr)
        r = report(yva, m.predict(Xva))
        print(f"C={C:<4} val {r}")
        if best is None or r["f1"] > best[1]["f1"]:
            best = (C, r, m)

    C, r, model = best
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    (MODEL_PATH.parent / "baseline_meta.json").write_text(json.dumps({"C": C, "val": r}, indent=2))
    print(f"\nsaved {MODEL_PATH.name} (C={C}) val={r}  total {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
