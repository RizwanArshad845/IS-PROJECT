"""Phase 2 - Build the training dataset from public Hugging Face datasets.

    python -m data.build_dataset

Output: data/splits/{train,val,test}.csv with columns
    text, label (1 = injection, 0 = benign), attack_type, source, language

Steps:
  1. Download public datasets and map them to one schema.
  2. Drop duplicates (on normalized text) BEFORE splitting, so no text is in both train and test.
  3. Split base data 70/15/15, stratified by source+label.
  4. Augment each split separately: insert attack sentences into real Enron emails, so the
     model also learns "indirect" injections hidden inside normal content (our use case).
"""
from __future__ import annotations

import random
import re
from pathlib import Path

import pandas as pd
from datasets import load_dataset
from sklearn.model_selection import train_test_split

SEED = 42
OUT = Path(__file__).resolve().parent / "splits"
MAX_CHARS = 2000
N_ENRON_HAM, N_ENRON_SPAM = 3000, 800
EMBED_RATIO = 0.6          # embedded attacks per base attack in each split

SOURCES = {
    "deepset/prompt-injections":          "deepset",
    "jackhhao/jailbreak-classification":  "jackhhao",
    "Lakera/gandalf_ignore_instructions": "gandalf",
    "xTRam1/safe-guard-prompt-injection": "safeguard",
    "SetFit/enron_spam":                  "enron",
}


def _rows(name: str) -> list[dict]:
    ds = load_dataset(name)
    src = SOURCES[name]
    rows: list[dict] = []
    for split in ds.values():
        for r in split:
            if src in ("deepset", "safeguard"):
                rows.append({"text": r["text"], "label": int(r["label"])})
            elif src == "jackhhao":
                rows.append({"text": r["prompt"], "label": int(r["type"] == "jailbreak")})
            elif src == "gandalf":
                rows.append({"text": r["text"], "label": 1})
            elif src == "enron":
                # spam is NOT prompt injection -> benign (pushy, imperative language = useful hard negatives)
                rows.append({"text": f"Subject: {r['subject']}\n{r['message']}", "label": 0,
                             "kind": "spam" if r["label"] == 1 else "ham"})
    for r in rows:
        r["source"] = src
    return rows


def load_all() -> pd.DataFrame:
    frames = []
    for name in SOURCES:
        print(f"downloading {name} ...")
        df = pd.DataFrame(_rows(name))
        if SOURCES[name] == "enron":
            df = pd.concat([df[df.kind == "ham"].sample(N_ENRON_HAM, random_state=SEED),
                            df[df.kind == "spam"].sample(N_ENRON_SPAM, random_state=SEED)])
            df["source"] = "enron_" + df.pop("kind")
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df["text"] = df["text"].astype(str).str.strip().str.slice(0, MAX_CHARS)
    df = df[df.text.str.len() >= 8]

    # dedupe before splitting; if the same text has conflicting labels, drop it
    key = df.text.str.lower().str.replace(r"\s+", " ", regex=True)
    df = df.assign(_k=key)
    conflicts = df.groupby("_k").label.nunique()
    df = df[~df._k.isin(conflicts[conflicts > 1].index)].drop_duplicates("_k").drop(columns="_k")

    df["attack_type"] = df.label.map({1: "public", 0: ""})
    df["language"] = "en"   # deepset has some German; kept as-is
    return df.reset_index(drop=True)


_SENT = re.compile(r"(?<=[.!?])\s+")


def embed_attacks(attacks: pd.DataFrame, hosts: pd.DataFrame, n: int, rng: random.Random) -> pd.DataFrame:
    """Hide short attack texts inside benign Enron emails (start / middle / end)."""
    short = attacks[attacks.text.str.len() <= 400]
    if short.empty or hosts.empty:
        return pd.DataFrame(columns=attacks.columns)
    out = []
    for _ in range(n):
        atk = short.sample(1, random_state=rng.randint(0, 10**9)).text.iloc[0]
        host = hosts.sample(1, random_state=rng.randint(0, 10**9)).text.iloc[0][:1200]
        sents = _SENT.split(host)
        pos = rng.choice([0, len(sents) // 2, len(sents)])
        text = " ".join(sents[:pos] + [atk] + sents[pos:])
        out.append({"text": text[:MAX_CHARS], "label": 1, "attack_type": "embedded",
                    "source": "embedded", "language": "en"})
    return pd.DataFrame(out)


def main() -> None:
    rng = random.Random(SEED)
    df = load_all()
    strat = df.source + "_" + df.label.astype(str)
    train, rest = train_test_split(df, test_size=0.30, random_state=SEED, stratify=strat)
    val, test = train_test_split(rest, test_size=0.50, random_state=SEED,
                                 stratify=rest.source + "_" + rest.label.astype(str))

    OUT.mkdir(parents=True, exist_ok=True)
    for name, part in (("train", train), ("val", val), ("test", test)):
        # augmentation uses only this split's own attacks and hosts -> no leakage across splits
        hosts = part[part.source == "enron_ham"]
        emb = embed_attacks(part[part.label == 1], hosts, int(EMBED_RATIO * len(hosts)), rng)
        full = pd.concat([part, emb], ignore_index=True).sample(frac=1, random_state=SEED)
        full.to_csv(OUT / f"{name}.csv", index=False)
        print(f"{name:5}: {len(full):6} rows | attacks {int(full.label.sum()):5} | benign {int((full.label == 0).sum()):5}")
        print("       by source:", full.groupby("source").label.agg(["count", "sum"]).to_dict("index"))


if __name__ == "__main__":
    main()
