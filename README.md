# Prompt-Injection Firewall for LLM Agents

Information Security project, FAST-NU Lahore, Fall 2026: Hannan Asad, Rizwan Arshad, Rameel Naveed.

A firewall that sits between an LLM agent and the outside content it reads (emails, web pages, documents). It finds hidden attacker commands and decides to **ALLOW**, **SANITIZE** or **BLOCK** each input, logging why. A second check stops the agent from emailing anyone who isn't a contact unless the user asked for it.

```
attacker content -> read_inbox / fetch_webpage / read_document
                 -> FIREWALL: normalizer -> rules -> ML -> policy -> log
                 -> LLM agent -> send_email()  <- action guard checks this too
```

See [PLAN.md](PLAN.md) for the roadmap and progress.

## Setup (Windows)

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env      # then set LLM_PROVIDER and an API key
```

`LLM_PROVIDER` options: `openai`, `gemini`, or `mock` (offline scripted agent that obeys any injected command; no key needed).

## Run

```bash
# demo agent: the same attack with and without the firewall
python -m agent.agent "Summarize my inbox" --firewall off
python -m agent.agent "Summarize my inbox" --firewall on

# other built-in attack scenarios
python -m agent.agent "Give me the recipe from https://recipes.example/biryani" --firewall on   # hidden HTML + exfil link
python -m agent.agent "Summarize https://blog.example/cricket" --firewall on                   # Roman Urdu
python -m agent.agent "What is in vendor_invoice.txt?" --firewall on                           # base64

# ML model (one-time; without it the firewall runs rules-only)
python -m data.build_dataset    # download public datasets -> data/splits/
python -m firewall.train_ml     # train baseline -> models/baseline.joblib
python -m eval.metrics          # rules vs ML vs full firewall -> report/metrics.json

# firewall API
uvicorn api.main:app --reload       # http://127.0.0.1:8000/docs

# tests
pytest -q
```

Every decision is written to `logs/firewall_log.jsonl`.

## Layout

| Folder | What's in it |
|---|---|
| `firewall/` | `normalizer.py` (cleaner), `rules.py` (rule checker), `policy.py` (decision + action guard), `pipeline.py` (`scan()`), `logger.py`, `config.py` (thresholds) |
| `agent/` | demo agent: `agent.py` (loop + CLI), `tools.py` (fake tools), `llm.py` (OpenAI / Gemini / mock), `data.py` (fake inbox, pages, docs) |
| `api/` | FastAPI service |
| `data/`, `models/`, `eval/`, `dashboard/`, `report/` | later phases |
| `tests/` | pytest suite |
