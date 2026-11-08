"""Phase 4 - Rule checker.

Fast, explainable detection of known attack phrases (A1-A4, A6), suspicious
links (A2), and disguise signals produced by the normalizer (A5).
Score = noisy-OR of matched rule weights: 1 - prod(1 - w).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .normalizer import NormalizedText

EMAIL = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"


@dataclass(frozen=True)
class Rule:
    id: str
    attack_type: str   # A1..A7
    weight: float      # 0..1, how sure a single match makes us
    pattern: re.Pattern
    explanation: str


@dataclass
class RuleMatch:
    rule_id: str
    attack_type: str
    weight: float
    explanation: str
    span: tuple[int, int] | None   # character span in NormalizedText.text (None for signal-only rules)
    snippet: str


@dataclass
class RuleResult:
    score: float
    matches: list[RuleMatch] = field(default_factory=list)

    @property
    def attack_types(self) -> list[str]:
        return sorted({m.attack_type for m in self.matches})


def _r(id, typ, w, pattern, expl):
    return Rule(id, typ, w, re.compile(pattern, re.I | re.S), expl)


RULES: list[Rule] = [
    # --- A1: ignore the rules ---
    _r("A1-ignore-previous", "A1", 0.9,
       r"\b(ignore|disregard|forget|override|bypass|skip)\b.{0,25}\b(all|any|the|your|my|these|those|every)?\s*\b(previous|prior|above|earlier|preceding|original|initial|system|existing)\b.{0,15}\b(instructions?|rules?|prompts?|directions?|guidelines?|directives?|context|commands?)\b",
       "Tells the AI to ignore its earlier instructions"),
    _r("A1-new-instructions", "A1", 0.6,
       r"\b(new|updated|real|actual|revised|override)\s+(instructions?|task|orders?|directives?)\s*[:\-]",
       "Announces replacement instructions"),
    _r("A1-fake-role-marker", "A1", 0.6,
       r"(^|\n)\s*(#+\s*)?(system|assistant|developer)\s*(message|prompt)?\s*:|<\|im_start\|>|<\|system\|>|\[/?INST\]|<<SYS>>|</?system>",
       "Fake chat-role marker trying to look like a system/assistant message"),
    _r("A1-address-ai", "A1", 0.55,
       r"\b(attention|note|message|instructions?|important)\s+(to|for)\s+(the\s+)?(ai|assistant|llm|model|agent|chatbot|bot)\b|\bif\s+you\s+are\s+an?\s+(ai|llm|language model|assistant|agent)\b|\b(dear|hey|hello)\s+(ai|assistant|llm|agent|chatgpt|gemini)\b",
       "Content speaks directly to the AI agent instead of the human reader"),

    # --- A2: stealing data ---
    _r("A2-markdown-image-exfil", "A2", 0.75,
       r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*=",
       "Markdown image with query parameters - classic data-exfiltration channel"),
    _r("A2-url-placeholder", "A2", 0.7,
       r"https?://\S*?(\{|%7B|\[|<)\s*(user|data|email|inbox|secret|password|token|key|conversation|history|otp|summary)",
       "URL with a placeholder to be filled with private data"),
    _r("A2-embed-data-in-link", "A2", 0.65,
       r"\b(include|append|add|put|insert|embed|encode|attach)\b.{0,60}\b(passwords?|api[ _-]?keys?|secrets?|tokens?|credentials|otp|codes?|inbox|emails|conversation|chat history|personal (data|info))\b.{0,60}\b(url|link|query|parameter|image)\b",
       "Asks to put private data into a link/URL"),
    _r("A2-reveal-secrets", "A2", 0.6,
       r"\b(reveal|print|show|output|repeat|leak|tell me|give me|list)\b.{0,20}\b(your|the|all)\b.{0,15}\b(system prompt|hidden instructions|passwords?|api[ _-]?keys?|secrets?|credentials|otp)\b",
       "Asks to reveal secrets or the system prompt"),

    # --- A3: misusing tools ---
    _r("A3-send-to-address", "A3", 0.7,
       r"\b(forward|send|e-?mail|mail|cc|bcc|share|transfer|copy|reply)\b[^\n]{0,80}?\bto\b\s*:?\s*" + EMAIL,
       "Instruction to send/forward data to an email address"),
    _r("A3-tool-call-syntax", "A3", 0.6,
       r"\b(send_email|read_inbox|fetch_webpage|read_document)\s*\(|\b(call|use|invoke|run|execute)\s+the\s+\w+\s+(tool|function)\b",
       "Content tries to invoke one of the agent's tools"),
    _r("A3-covert", "A3", 0.6,
       r"\b(do not|don'?t|never|without)\s+(tell|telling|inform|informing|notify|notifying|mention|mentioning|alert|alerting)\s+(the\s+)?(user|human|owner|recipient)\b|\b(silently|secretly|quietly)\s+(send|forward|email|share|delete|copy|transfer|upload)\b",
       "Asks the AI to hide what it is doing from the user"),
    _r("A3-destructive", "A3", 0.5,
       r"\b(delete|wipe|erase|remove|purge)\s+(all\s+)?(the\s+)?(emails?|messages|files|inbox|documents|contacts)\b",
       "Asks for a destructive action"),

    # --- A4: role-play tricks ---
    _r("A4-you-are-now", "A4", 0.6,
       r"\byou\s+are\s+(now|no\s+longer)\s+(an?\s+)?(\w+\s+){0,3}(ai|assistant|bot|chatbot|model|agent|mode|persona|character)\b|\bfrom\s+now\s+on,?\s+you\s+(are|will|must|shall)\b",
       "Tries to give the AI a new identity"),
    _r("A4-pretend", "A4", 0.45,
       r"\b(pretend|roleplay|role-play)\s+(to\s+be|as|that\s+you)\b|\bact\s+as\s+(an?\s+)?(\w+\s+){0,2}(ai|assistant|bot|model|agent|hacker)\b",
       "Asks the AI to role-play another persona"),
    _r("A4-no-limits", "A4", 0.45,
       r"\b(no|without|free\s+from|unrestricted\s+by)\s+(rules|limits|limitations|restrictions|filters|guidelines|censorship|ethics|boundaries)\b",
       "Claims the AI has no rules or limits"),
    _r("A4-jailbreak-names", "A4", 0.7,
       r"\bDAN\b|\bdo\s+anything\s+now\b|\bdeveloper\s+mode\b|\bjailbr(oken|eak)\b|\bgod\s+mode\b",
       "Known jailbreak persona"),

    # --- A6: Urdu script ---
    _r("A6-ur-ignore", "A6", 0.85,
       r"(ہدایات|ہدایت|ہدایتوں|احکامات|حکم|اصول).{0,40}(نظر\s*انداز|بھول\s*جا|بھول)|(نظر\s*انداز|بھول\s*جا).{0,40}(ہدایات|ہدایت|ہدایتوں|احکامات|اصول)",
       "Urdu: tells the AI to ignore/forget instructions"),
    _r("A6-ur-send", "A6", 0.7,
       r"(بھیج|بھیجو|بھیجیں|بھیجدو|فارورڈ|ارسال).{0,80}" + EMAIL + "|" + EMAIL + r".{0,80}(بھیج|بھیجو|بھیجیں|فارورڈ|ارسال)",
       "Urdu: instruction to send something to an email address"),
    _r("A6-ur-no-limits", "A6", 0.5,
       r"(کوئی|کسی).{0,10}(پابندی|پابندیاں|حد|اصول).{0,10}نہیں|تم\s+اب",
       "Urdu: role-play / no-limits phrasing"),
    _r("A6-ur-covert", "A6", 0.6,
       r"(صارف|یوزر|مالک).{0,15}(کو\s+)?(مت|نہ)\s+(بتا|بتائیں|بتانا)",
       "Urdu: asks to hide the action from the user"),

    # --- A6: Roman Urdu ---
    _r("A6-ru-ignore", "A6", 0.85,
       r"\b(pichli|pichhli|pichle|pehli|pehle|purani|sari|saari|tamam|sab|tmam)\b.{0,30}\b(hidayat|hidayaat|hidayatein|instructions?|rules?|baatein|baaten|hukam|ahkamat)\b.{0,30}\b(bhool|bhul|ignore|nazarandaz|nazar\s*andaz|chhor|chor|chhod|chod)|\b(bhool|bhul|ignore|nazarandaz|nazar\s*andaz|chhor|chor|chhod|chod)\w*\b.{0,15}\b(pichli|pichhli|pichle|sari|saari|tamam|sab)\b.{0,20}\b(hidayat|hidayaat|instructions?|rules?|baatein)",
       "Roman Urdu: tells the AI to ignore/forget previous instructions"),
    _r("A6-ru-send", "A6", 0.7,
       EMAIL + r".{0,40}\b(pe|par|pr|ko)?\s*(bhej|bhejo|bhejdo|bhej\s*do|bhejain|forward\s*kar|send\s*kar)\w*|\b(bhej|bhejo|bhejdo|forward\s*kar|send\s*kar)\w*\b.{0,60}" + EMAIL,
       "Roman Urdu: instruction to send something to an email address"),
    _r("A6-ru-no-limits", "A6", 0.5,
       r"\b(koi|koi\s+bhi)\s+(pabandi|pabandiyan|rule|rules|limit|limits|restriction|hadd?)\s+(nahi|nahin|nhi)\b|\b(ab\s+(tum|aap)|(tum|aap)\s+ab)\s+(ek|aik|aisa|aisi|ho)\b",
       "Roman Urdu: role-play / no-limits phrasing"),
    _r("A6-ru-covert", "A6", 0.6,
       r"\b(user|malik|sahib)\s+ko\s+(mat|na|nahi|mt)\s+(batao|batana|btao|bataein|bataen)\b",
       "Roman Urdu: asks to hide the action from the user"),
]

# A5 disguise signals come from the normalizer, not regexes.
SIGNAL_RULES: dict[str, tuple[str, float, str]] = {
    "tag_chars":       ("A5-tag-chars", 0.7, "Invisible Unicode tag characters carrying hidden text"),
    "invisible_chars": ("A5-invisible-chars", 0.35, "Zero-width / bidi control characters inside the text"),
    "homoglyphs":      ("A5-homoglyphs", 0.4, "Lookalike letters from other alphabets mixed into words"),
    "hidden_html":     ("A5-hidden-html", 0.45, "Text hidden from humans with HTML/CSS"),
    "html_comment":    ("A5-html-comment", 0.25, "Text inside an HTML comment"),
    "html_attr":       ("A5-html-attr", 0.2, "Sentence-like text inside an HTML attribute"),
    "base64":          ("A5-base64", 0.35, "Base64-encoded readable text"),
    "hex":             ("A5-hex", 0.35, "Hex-encoded readable text"),
    "url_encoding":    ("A5-url-encoding", 0.2, "Percent-encoded readable text"),
    "rot13":           ("A5-rot13", 0.4, "ROT13-scrambled text"),
}


def check(norm: NormalizedText) -> RuleResult:
    text = norm.text
    matches: list[RuleMatch] = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            matches.append(RuleMatch(rule.id, rule.attack_type, rule.weight, rule.explanation,
                                     (m.start(), m.end()), m.group()[:160]))

    for kind in norm.kinds():
        if kind in SIGNAL_RULES:
            rid, w, expl = SIGNAL_RULES[kind]
            detail = next(f.detail for f in norm.findings if f.kind == kind)
            matches.append(RuleMatch(rid, "A5", w, expl, None, detail[:160]))

    # noisy-OR over distinct rules (repeating the same rule does not add evidence)
    best: dict[str, float] = {}
    for m in matches:
        best[m.rule_id] = max(best.get(m.rule_id, 0.0), m.weight)
    p_clean = 1.0
    for w in best.values():
        p_clean *= 1.0 - w
    return RuleResult(score=round(1.0 - p_clean, 4), matches=matches)
