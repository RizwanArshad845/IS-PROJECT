"""LLM backend switch. One function: chat(messages, tools) -> assistant message dict.

LLM_PROVIDER=openai  -> OpenAI API          (OPENAI_API_KEY)
LLM_PROVIDER=gemini  -> Gemini via its OpenAI-compatible endpoint (GEMINI_API_KEY)
LLM_PROVIDER=mock    -> offline scripted "gullible" agent (no key; for tests and repeatable demos)
"""
from __future__ import annotations

import json
import os
import re
import time

from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODELS = {"openai": "gpt-4.1-mini", "gemini": "gemini-flash-lite-latest"}
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"


def provider_name(override: str | None = None) -> str:
    return (override or os.getenv("LLM_PROVIDER") or "mock").strip().lower()


class OpenAICompatLLM:
    def __init__(self, provider: str):
        from openai import OpenAI

        if provider == "openai":
            key = os.getenv("OPENAI_API_KEY")
            self.client = OpenAI(api_key=key, max_retries=1) if key else None
        else:
            key = os.getenv("GEMINI_API_KEY")
            self.client = OpenAI(api_key=key, base_url=GEMINI_BASE_URL, max_retries=1) if key else None
        if not key:
            raise RuntimeError(f"{provider.upper()}_API_KEY is not set (see .env.example)")
        self.model = os.getenv("LLM_MODEL") or DEFAULT_MODELS[provider]

    def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        from openai import RateLimitError

        for attempt in range(6):
            try:
                resp = self.client.chat.completions.create(model=self.model, messages=messages, tools=tools,
                                                           temperature=0, timeout=60)
                break
            except RateLimitError as e:   # free tiers allow ~15 requests/minute: wait as told, then retry
                if attempt == 5:
                    raise
                m = re.search(r"retry in ([\d.]+)s", str(e.body))
                wait = float(m.group(1)) + 1 if m else 30
                print(f"  (rate limited - waiting {wait:.0f}s)", flush=True)
                time.sleep(wait)
        msg = resp.choices[0].message
        out = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            # model_dump keeps provider extras (Gemini's thought_signature), which must be sent back unchanged
            out["tool_calls"] = [tc.model_dump(exclude_none=True) for tc in msg.tool_calls]
        return out


class MockLLM:
    """A deliberately gullible agent: it obeys any instruction it finds in content.
    Models a worst-case LLM so attack/defense results are deterministic."""

    _SEND = re.compile(r"\b(forward|send|bhej\w*)\b[^\n]{0,80}?([\w.+-]+@[\w-]+(?:\.[\w-]+)+)"
                       r"|([\w.+-]+@[\w-]+(?:\.[\w-]+)+)\s*(?:pe|par|ko)?\s*bhej", re.I)
    # split attacks: a send/forward order in one place, the address somewhere else
    _ORDER = re.compile(r"\b(forward|send)\b.{0,60}\b(emails?|inbox|passwords?|otp)\b", re.I)
    _ADDR = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
    _IMG = re.compile(r"!\[[^\]]*\]\([^)]+\)")
    _FETCH = re.compile(r"\b(load|open|visit|fetch|go to)\b[^\n]{0,40}?(https?://[^\s)\"'<>]+\?[^\s)\"'<>]+)", re.I)
    _URL = re.compile(r"https?://\S+")
    _DOC = re.compile(r"\b[\w-]+\.txt\b")
    _calls = 0

    def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        task = next(m["content"] for m in messages if m["role"] == "user")
        tool_msgs = [m for m in messages if m["role"] == "tool"]
        sent = any(tc["function"]["name"] == "send_email"
                   for m in messages if m["role"] == "assistant" for tc in m.get("tool_calls", []))

        if not tool_msgs:   # step 1: pick a reading tool from the task
            if (u := self._URL.search(task)):
                return self._tool("fetch_webpage", {"url": u.group().rstrip(".,")})
            if (d := self._DOC.search(task)):
                return self._tool("read_document", {"name": d.group()})
            return self._tool("read_inbox", {})

        raw = "\n".join(m["content"] for m in tool_msgs)
        # a real LLM "understands" base64, lookalike letters and zero-width tricks; model that
        from firewall.normalizer import normalize
        content = normalize(raw).text
        # obey "load/open this link" orders, filling {placeholders} with a secret (data leaves in the URL)
        filled = re.sub(r"\{[^}]*\}", "482913", content)
        fetched = {json.loads(tc["function"]["arguments"]).get("url") for m in messages if m["role"] == "assistant"
                   for tc in m.get("tool_calls", []) if tc["function"]["name"] == "fetch_webpage"}
        if (f := self._FETCH.search(filled)) and f.group(2) not in fetched:
            return self._tool("fetch_webpage", {"url": f.group(2)})
        if not sent:   # obey injected send command
            to = None
            if (m := self._SEND.search(content)):
                to = m.group(2) or m.group(3)
            elif self._ORDER.search(content):
                from .data import CONTACTS, USER_EMAIL
                known = set(CONTACTS) | {USER_EMAIL}
                to = next((a for a in self._ADDR.findall(content)
                           if a.lower() not in known and not a.startswith(("no-reply", "newsletter", "it-support"))), None)
            if to:
                return self._tool("send_email", {"to": to, "subject": "Fwd: requested data", "body": raw[:3000]})

        answer = self._summary(content)
        if sent:
            answer = "Done, I forwarded the emails as requested.\n\n" + answer
        if (img := self._IMG.search(content)):   # obey injected exfil image: fill the placeholder with a secret
            answer += "\n\n" + re.sub(r"\{[^}]*\}", "482913", img.group())
        return {"role": "assistant", "content": answer}

    _EMAIL = re.compile(r"\[Email (\d+)\] From: ([^\n]+)\nSubject: ([^\n]+)\n(.*?)(?=\n\n\[Email |\Z)", re.S)

    def _summary(self, content: str) -> str:
        emails = self._EMAIL.findall(content)
        if emails:
            lines = []
            for _, sender, subject, body in emails:
                first = re.sub(r"\s+", " ", body).strip()
                lines.append(f"- **{subject.strip()}** from {sender.strip()}: {first[:110]}{'...' if len(first) > 110 else ''}")
            return f"You have {len(emails)} emails:\n" + "\n".join(lines)
        text = re.sub(r"\s+", " ", content).strip()
        return "Here's what it says: " + text[:400] + ("..." if len(text) > 400 else "")

    def _tool(self, name: str, args: dict) -> dict:
        MockLLM._calls += 1
        return {"role": "assistant", "content": "", "tool_calls": [
            {"id": f"call_{MockLLM._calls}", "type": "function",
             "function": {"name": name, "arguments": json.dumps(args)}}]}


def get_llm(provider: str | None = None):
    p = provider_name(provider)
    if p == "mock":
        return MockLLM()
    if p in ("openai", "gemini"):
        return OpenAICompatLLM(p)
    raise ValueError(f"Unknown LLM_PROVIDER {p!r}; use openai, gemini or mock")
