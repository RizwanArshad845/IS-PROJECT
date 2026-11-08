"""Tunable thresholds for the decision step."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BLOCK_THRESHOLD = 0.85      # combined score >= this -> BLOCK
SANITIZE_THRESHOLD = 0.5    # combined score >= this -> SANITIZE, else ALLOW
TOOL_INTENT_WEIGHT = 0.4    # extra evidence when content asks for a tool the user didn't ask for

LOG_PATH = ROOT / "logs" / "firewall_log.jsonl"
