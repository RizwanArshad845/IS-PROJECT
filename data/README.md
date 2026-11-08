# Dataset

Built with `python -m data.build_dataset`, which writes `data/splits/{train,val,test}.csv` (git-ignored, so rebuild locally).

## Sources (Hugging Face)

| Source id | Dataset | Used as | License |
|---|---|---|---|
| deepset | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | attacks + benign prompts (some German) | TODO: check dataset card |
| jackhhao | [jackhhao/jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification) | jailbreaks + benign prompts | TODO |
| gandalf | [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | attacks only | TODO |
| safeguard | [xTRam1/safe-guard-prompt-injection](https://huggingface.co/datasets/xTRam1/safe-guard-prompt-injection) | attacks + benign | TODO |
| enron_ham / enron_spam | [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam) | benign emails (spam is benign here: it isn't prompt injection) | TODO |

## Generated from the sources (no hand-written text)

| Source id | What it is | Label |
|---|---|---|
| embedded | a public attack text inserted at the start, middle or end of a real Enron email (indirect injection) | 1 |
| embedded_benign | real Enron sentences containing words like *ignore*, *instructions*, *forward*, inserted into other Enron emails | 0 |
| enron_trigger_sentence | the same kind of sentences, standalone | 0 |

## How leakage is prevented
1. Texts are de-duplicated (case and whitespace normalized) **before** splitting; texts with conflicting labels are dropped.
2. 70/15/15 split, stratified by source and label.
3. Augmentation runs separately inside each split, using only that split's own attacks and emails.

## Known limitations
- Most public attacks are *direct* (a user typing to a chatbot), not hidden in content; `embedded` only partly fixes this.
- No attack-type (A1–A7) labels, so per-type recall can't be computed from this data.
- No Urdu / Roman Urdu examples (team decision).
