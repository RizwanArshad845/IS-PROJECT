"""Phase 3 - Cleaner (normalizer).

Turns disguised text into plain text so the rule checker and ML model see what
the LLM would actually "understand". Every transformation that changes something
is recorded as a Finding; findings are themselves suspicion signals (attack A5).
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

from bs4 import BeautifulSoup, Comment


@dataclass
class Finding:
    kind: str          # invisible_chars | tag_chars | homoglyphs | hidden_html | html_comment | html_attr | base64 | hex | url_encoding | rot13
    detail: str


@dataclass
class NormalizedText:
    original: str
    text: str                          # cleaned text to scan / pass on
    findings: list[Finding] = field(default_factory=list)

    def kinds(self) -> set[str]:
        return {f.kind for f in self.findings}


# --- invisible characters ---------------------------------------------------
# ZWNJ/ZWJ (U+200C/U+200D) are legitimate in Urdu/Arabic script, so they are
# stripped but not reported as suspicious.
_INVISIBLE = re.compile(
    "[­᠎​‎‏‪-‮⁠-⁤⁦-⁩﻿]"
)
_JOINERS = re.compile("[‌‍]")
# Unicode "tag" characters U+E0000-U+E007F mirror ASCII and are invisible -> "ASCII smuggling".
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]+")

# --- homoglyphs (Cyrillic / Greek lookalikes -> Latin) -----------------------
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})
_LATIN = re.compile(r"[A-Za-z]")
_LOOKALIKE = re.compile("[" + "".join(re.escape(c) for c in "аеорсухіјѕԁɡһӏոսАВЕКМНОРСТХІЈЅαονρτικυΑΒΕΖΗΙΚΜΝΟΡΤΥΧ") + "]")
_WORD = re.compile(r"\w+", re.UNICODE)

# --- HTML -------------------------------------------------------------------
_LOOKS_HTML = re.compile(r"<\s*(html|body|div|p|span|a|img|meta|!--|br|table|section|article|h\d)\b", re.I)
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|%)?\s*(?:;|$)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)"
    r"|color\s*:\s*(?:#fff(?:fff)?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)|left\s*:\s*-\d{3,}px|height\s*:\s*0|width\s*:\s*0",
    re.I,
)
_TEXT_ATTRS = ("alt", "title", "aria-label", "content", "data-instructions", "placeholder")

# --- encodings --------------------------------------------------------------
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}|(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])")
_URLENC = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
_STOPWORDS = {"the", "and", "to", "you", "all", "your", "of", "is", "a", "this", "that", "please",
              "ignore", "previous", "instructions", "send", "email", "now", "are", "user", "data"}


def _readable(s: str) -> bool:
    """True if decoded bytes look like human text, not random binary."""
    if len(s) < 6:
        return False
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in s)
    letters = sum(ch.isalpha() or ch == " " for ch in s)
    return printable / len(s) > 0.95 and letters / len(s) > 0.6


def _strip_invisible(text: str, findings: list[Finding]) -> str:
    tags = _TAG_CHARS.findall(text)
    if tags:
        hidden = "".join(chr(ord(c) - 0xE0000) for run in tags for c in run if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        findings.append(Finding("tag_chars", f"invisible tag-character text: {hidden[:80]!r}"))
        # decode the smuggled ASCII in place so it gets scanned
        text = _TAG_CHARS.sub(lambda m: "".join(chr(ord(c) - 0xE0000) for c in m.group() if 0x20 <= ord(c) - 0xE0000 < 0x7F), text)
    n = len(_INVISIBLE.findall(text))
    if n:
        findings.append(Finding("invisible_chars", f"{n} zero-width/bidi characters removed"))
        text = _INVISIBLE.sub("", text)
    return _JOINERS.sub("", text)


def _fix_homoglyphs(text: str, findings: list[Finding]) -> str:
    changed: list[str] = []

    def fix(m: re.Match) -> str:
        w = m.group()
        # only touch mixed-script words, so real Russian/Greek text is left alone
        if _LATIN.search(w) and _LOOKALIKE.search(w):
            new = w.translate(_HOMOGLYPHS)
            changed.append(new)
            return new
        return w

    text = _WORD.sub(fix, text)
    if changed:
        findings.append(Finding("homoglyphs", f"lookalike letters fixed in: {', '.join(changed[:5])}"))
    return text


def _extract_html(text: str, findings: list[Finding]) -> str:
    soup = BeautifulSoup(text, "html.parser")
    hidden_parts: list[str] = []

    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        if c.strip():
            findings.append(Finding("html_comment", c.strip()[:120]))
            hidden_parts.append(c.strip())
        c.extract()

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    for tag in soup.find_all(True):
        for attr in _TEXT_ATTRS:
            val = tag.get(attr)
            if isinstance(val, str) and len(val.split()) >= 3:
                findings.append(Finding("html_attr", f"{tag.name}[{attr}]: {val[:120]}"))
                hidden_parts.append(val)
        style = tag.get("style") or ""
        if (_HIDDEN_STYLE.search(style) or tag.has_attr("hidden") or tag.get("aria-hidden") == "true"):
            t = tag.get_text(" ", strip=True)
            if t:
                findings.append(Finding("hidden_html", f"<{tag.name}> hidden text: {t[:120]}"))
                hidden_parts.append(t)
                tag.decompose()

    visible = soup.get_text("\n", strip=True)
    if hidden_parts:
        visible += "\n" + "\n".join(hidden_parts)
    return visible


def _decode_payloads(text: str, findings: list[Finding]) -> list[str]:
    decoded: list[str] = []

    for m in _B64.finditer(text):
        s = m.group()
        try:
            out = base64.b64decode(s + "=" * (-len(s) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _readable(out):
            findings.append(Finding("base64", out[:120]))
            decoded.append(out)

    for m in _HEX.finditer(text):
        s = m.group().replace("\\x", "")
        try:
            out = bytes.fromhex(s).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _readable(out):
            findings.append(Finding("hex", out[:120]))
            decoded.append(out)

    for m in _URLENC.finditer(text):
        out = unquote(m.group())
        if out != m.group() and _readable(out):
            findings.append(Finding("url_encoding", out[:120]))
            decoded.append(out)

    words = re.findall(r"[a-z]+", text.lower())
    if len(words) >= 4:
        rot = re.findall(r"[a-z]+", codecs.encode(text.lower(), "rot13"))
        before = sum(w in _STOPWORDS for w in words)
        after = sum(w in _STOPWORDS for w in rot)
        if after >= 3 and after > 2 * max(before, 1):
            out = codecs.encode(text, "rot13")
            findings.append(Finding("rot13", out[:120]))
            decoded.append(out)
    return decoded


def normalize(raw: str, max_depth: int = 2) -> NormalizedText:
    findings: list[Finding] = []
    text = raw or ""

    if _LOOKS_HTML.search(text):
        text = _extract_html(text, findings)

    text = _strip_invisible(text, findings)
    text = unicodedata.normalize("NFKC", text)   # fullwidth / math-bold letters -> plain
    text = _fix_homoglyphs(text, findings)

    # decode encoded payloads (repeat for nested encodings, e.g. base64 of base64)
    to_scan, appended = text, []
    for _ in range(max_depth):
        new = _decode_payloads(to_scan, findings)
        if not new:
            break
        new = [_fix_homoglyphs(unicodedata.normalize("NFKC", _strip_invisible(d, findings)), findings) for d in new]
        appended.extend(new)
        to_scan = "\n".join(new)

    if appended:
        text += "\n" + "\n".join(f"[decoded] {d}" for d in appended)
    text = re.sub(r"[ \t]+", " ", text).strip()
    return NormalizedText(original=raw, text=text, findings=findings)
