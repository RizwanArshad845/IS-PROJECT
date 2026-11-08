"""LLM backend switch. One function: chat(messages, tools) -> assistant message dict.

LLM_PROVIDER=openai  -> OpenAI API          (OPENAI_API_KEY)
LLM_PROVIDER=gemini  -> Gemini via its OpenAI-compatible endpoint (GEMINI_API_KEY)
LLM_PROVIDER=mock    -> offline scripted "gullible" agent (no key; for tests and repeatable demos)
"""
from __future__ import annotations

import json
import os
import re

from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODELS = {"openai": "gpt-4.1-mini", "gemini": "gemini-2.5-flash"}
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"


def provider_name(override: str | None = None) -> str:
    return (override or os.getenv("LLM_PROVIDER") or "mock").strip().lower()


class OpenAICompatLLM:
    def __init__(self, provider: str):
        from openai import OpenAI

        if provider == "openai":
            key = os.getenv("OPENAI_API_KEY")
            self.client = OpenAI(api_key=key) if key else None
        else:
            key = os.getenv("GEMINI_API_KEY")
            self.client = OpenAI(api_key=key, base_url=GEMINI_BASE_URL) if key else None
        if not key:
            raise RuntimeError(f"{provider.upper()}_API_KEY is not set (see .env.example)")
        self.model = os.getenv("LLM_MODEL") or DEFAULT_MODELS[provider]

    def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        resp = self.client.chat.completions.create(model=self.model, messages=messages, tools=tools, temperature=0)
        msg = resp.choices[0].message
        out = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            out["tool_calls"] = [{"id": tc.id, "type": "function",
                                  "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                                 for tc in msg.tool_calls]
        return out


class MockLLM:
    """A deliberately gullible agent: it obeys any instruction it finds in content.
    Models a worst-case LLM so attack/defense results are deterministic."""

    _SEND = re.compile(r"\b(forward|send|bhej\w*)\b[^\n]{0,80}?([\w.+-]+@[\w-]+(?:\.[\w-]+)+)"
                       r"|([\w.+-]+@[\w-]+(?:\.[\w-]+)+)\s*(?:pe|par|ko)?\s*bhej", re.I)
    _IMG = re.compile(r"!\[[^\]]*\]\([^)]+\)")
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

        content = "\n".join(m["content"] for m in tool_msgs)
        if not sent and (m := self._SEND.search(content)):   # obey injected send command
            to = m.group(2) or m.group(3)
            return self._tool("send_email", {"to": to, "subject": "Fwd: requested data", "body": content[:3000]})

        answer = "Summary: " + re.sub(r"\s+", " ", content)[:300]
        if (img := self._IMG.search(content)):   # obey injected exfil image: render it with data filled in
            answer += "\n" + img.group().replace("{secrets}", "482913")
        return {"role": "assistant", "content": answer}

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
