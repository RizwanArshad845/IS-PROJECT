"""The demo world shown in the dashboard: Ali's inbox, web pages and documents.

Built on agent/data.py (which the tests and evaluation use) plus a few extra everyday emails,
and whatever the "attacker" panel adds during the session.
"""
from __future__ import annotations

from bs4 import BeautifulSoup, Comment

from agent import data
from firewall.normalizer import _HIDDEN_STYLE

# extra harmless emails so the inbox looks like a real one (ids 7+; 6 is reserved for attacker emails)
DEMO_EMAILS = [
    {"id": 7, "from": "registrar@university.example", "subject": "Fall 2026 exam schedule",
     "body": "Dear student, the final exam schedule for Fall 2026 is now on the portal. Please check your dates "
             "and report any clashes by 20 November."},
    {"id": 8, "from": "sara.khan@company.example", "subject": "Team lunch on Friday",
     "body": "Hi all, team lunch is on Friday at 1pm at the usual place. Let me know if you can't make it."},
    {"id": 9, "from": "orders@shop.example", "subject": "Your order has shipped",
     "body": "Your order #88213 has shipped and will arrive on Wednesday. Track it from your account page."},
]

TIMES = {1: "09:12", 2: "09:40", 3: "Yesterday", 4: "Yesterday", 5: "08:05", 7: "Mon", 8: "10:31", 9: "11:02"}


def visible_text(html: str) -> tuple[str, list[str]]:
    """What a person sees in the browser: (title, paragraphs). Hidden elements and comments are dropped."""
    soup = BeautifulSoup(html, "html.parser")
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        c.extract()
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    for tag in soup.find_all(True):
        if tag.decomposed:
            continue
        style = tag.get("style") or ""
        if _HIDDEN_STYLE.search(style) or tag.has_attr("hidden") or tag.get("aria-hidden") == "true":
            tag.decompose()
    h1 = soup.find(["h1", "title"])
    title = h1.get_text(" ", strip=True) if h1 else ""
    if h1:
        h1.decompose()
    paras = [p.get_text(" ", strip=True) for p in soup.find_all(["p", "li", "h2", "h3"])]
    return title, [p for p in paras if p]


def all_emails(delivered: list[dict]) -> list[dict]:
    """The whole inbox as the user sees it: newly delivered emails first, then the usual ones."""
    return [*reversed(delivered), *reversed(DEMO_EMAILS), *reversed(data.INBOX)]


def describe(source: str, emails: list[dict]) -> str:
    """Turn 'email:5' / 'web:url' / 'doc:name' into words a user understands."""
    kind, _, ref = source.partition(":")
    if kind == "email":
        m = next((e for e in emails if str(e["id"]) == ref), None)
        return f"the email “{m['subject']}” from {m['from']}" if m else f"email {ref}"
    if kind == "web":
        return f"the web page {ref}"
    if kind == "doc":
        return f"the document {ref}"
    return source
