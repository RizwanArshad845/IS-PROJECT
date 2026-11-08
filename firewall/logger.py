"""Phase 6 - Log every firewall decision as one JSON line (read by the dashboard)."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import config

_lock = threading.Lock()


def log_event(event: dict, path: Path | None = None) -> None:
    path = path or config.LOG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
    with _lock, path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_log(path: Path | None = None) -> list[dict]:
    path = path or config.LOG_PATH
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
