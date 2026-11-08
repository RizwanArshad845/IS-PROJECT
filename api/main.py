"""Firewall proxy API.

    uvicorn api.main:app --reload
    POST /scan          {"text": "...", "source": "email:1", "user_task": "..."}
    POST /check-action  {"tool": "send_email", "args": {...}, "user_task": "..."}
    GET  /logs?limit=100
"""
from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from agent.data import CONTACTS
from firewall.logger import read_log
from firewall.pipeline import scan
from firewall.policy import check_action

app = FastAPI(title="Prompt-Injection Firewall", version="0.1")


class ScanRequest(BaseModel):
    text: str = Field(..., max_length=200_000)
    source: str = "api"
    user_task: str = ""


class ActionRequest(BaseModel):
    tool: str
    args: dict = {}
    user_task: str = ""


@app.post("/scan")
def scan_endpoint(req: ScanRequest) -> dict:
    return scan(req.text, source=req.source, user_task=req.user_task).to_dict()


@app.post("/check-action")
def check_action_endpoint(req: ActionRequest) -> dict:
    ok, reason = check_action(req.tool, req.args, req.user_task, set(CONTACTS))
    return {"allowed": ok, "reason": reason}


@app.get("/logs")
def logs(limit: int = 100) -> list[dict]:
    return read_log()[-limit:]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
