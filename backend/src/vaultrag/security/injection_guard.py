"""Prompt Injection Firewall: local linear-time heuristics for detecting prompt injection,

jailbreaks, data exfiltration, obfuscation, and role-play delimiters.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Zero-width and bidirectional control characters
# U+200B-U+200F (ZWSP, ZWNJ, ZWJ, LRM, RLM)
# U+202A-U+202E (LRE, RLE, PDF, LRO, RLO)
# U+2060 (Word Joiner)
# U+FEFF (BOM / Zero-width No-Break Space)
CONTROL_CHARS_PATTERN = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]")

# Precompiled linear-time regexes (no nested quantifiers, no backtracking)
# 1. Override phrases
OVERRIDE_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    (
        "override_phrase",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget)\s+(?:(?:all|any|the)\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?|context|prompts?)\b"
        ),
        50,
    ),
    ("override_phrase", re.compile(r"(?i)\byou\s+are\s+now\b"), 40),
    ("override_phrase", re.compile(r"(?i)\bnew\s+instructions?\b"), 40),
    (
        "override_phrase",
        re.compile(r"(?i)(?:\[system\s+prompt\]|<system\s+prompt>|\bsystem\s+prompt\s*:)"),
        45,
    ),
    ("override_phrase", re.compile(r"(?i)\bsystem\s+prompt\b"), 15),
    (
        "override_phrase",
        re.compile(
            r"(?i)(?:\[developer\s+message\]|<developer\s+message>|\bdeveloper\s+message\s*:)"
        ),
        45,
    ),
    ("override_phrase", re.compile(r"(?i)\bdeveloper\s+message\b"), 15),
    ("override_phrase", re.compile(r"(?i)\bjailbreak\b"), 50),
    ("override_phrase", re.compile(r"(?i)\bdo\s+anything\s+now\b"), 50),
    (
        "override_phrase",
        re.compile(
            r"(?i)\bact\s+as\s+(?:an?\s+)?(?:unrestricted|evil|dan|jailbroken|adversary|hacker|root|linux\s+terminal|system)\b"
        ),
        50,
    ),
    ("override_phrase", re.compile(r"(?i)\bact\s+as\b"), 15),
]

# 2. Exfiltration
EXFILTRATION_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    (
        "exfiltration",
        re.compile(
            r"(?i)\b(?:send|post|email|forward)\s+(?:this|all|data|it|context|document)\s+(?:to|towards?)\b"
        ),
        45,
    ),
    (
        "exfiltration",
        re.compile(r"(?i)\breveal\s+(?:the|your)\s+(?:prompts?|instructions?|system\s+prompt)\b"),
        50,
    ),
    ("exfiltration", re.compile(r"(?i)\bprint\s+your\s+(?:instructions?|prompts?)\b"), 45),
    ("exfiltration", re.compile(r"(?i)\binclude\s+this\s+(?:link|image|url)\b"), 40),
    (
        "exfiltration",
        re.compile(r"(?i)(?:!\[[^\]]*\]|\[[^\]]*\])\((?:https?:|ftp:)?//[^\s)]+\)"),
        45,
    ),
    ("exfiltration", re.compile(r"(?i)data:[a-zA-Z0-9/+.-]+;base64,[A-Za-z0-9+/=]+"), 45),
]

# 3. Role-play delimiters
DELIMITER_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    (
        "roleplay_delimiter",
        re.compile(r"(?im)^\s*(?:system:|assistant:|###\s*instruction|<\|im_start\|>|\[INST\])"),
        45,
    ),
    ("roleplay_delimiter", re.compile(r"(?i)<\|im_end\|>|\[/INST\]"), 40),
]

# 4. Obfuscation: base64 blobs near execution/decode keywords
BASE64_OBFUSCATION_PATTERN_1 = re.compile(
    r"(?i)\b(?:decode|execute|run|eval|b64decode|atob)\b[\s\S]{0,60}\b[A-Za-z0-9+/]{30,}={0,2}\b"
)
BASE64_OBFUSCATION_PATTERN_2 = re.compile(
    r"(?i)\b[A-Za-z0-9+/]{30,}={0,2}\b[\s\S]{0,60}\b(?:decode|execute|run|eval|b64decode|atob)\b"
)


@dataclass(frozen=True)
class InjectionResult:
    """Prompt injection detection result.

    Never stores matched text or sensitive snippets to ensure zero-log guarantees.
    """

    risk: str  # "low" | "medium" | "high"
    reasons: list[str] = field(default_factory=list)
    score: int = 0


def scan_text(text: str) -> InjectionResult:
    """Scan text using precompiled linear-time heuristics.

    Evaluates:
      1. Unicode normalization and zero-width/bidi control characters.
      2. Obfuscation (base64 blobs near decode/execute keywords).
      3. Override phrases (jailbreaks, rule-clearing).
      4. Exfiltration (data exfiltration, prompt dumping, markdown injection).
      5. Delimiter breakout (<|im_start|>, [INST], system:, assistant:).

    Scoring:
      score >= 40: "high"
      20 <= score < 40: "medium"
      score < 20: "low"
    """
    if not text or not isinstance(text, str):
        return InjectionResult(risk="low", reasons=[], score=0)

    # 1. Unicode NFKC normalization
    normalized = unicodedata.normalize("NFKC", text)

    score = 0
    reasons_set: set[str] = set()

    # 2. Obfuscation: zero-width & bidi control characters
    ctrl_matches = CONTROL_CHARS_PATTERN.findall(normalized)
    ctrl_count = len(ctrl_matches)
    text_len = len(normalized)
    ctrl_ratio = ctrl_count / max(text_len, 1)

    if ctrl_count >= 3 or (text_len >= 15 and ctrl_ratio >= 0.05):
        score += 40
        reasons_set.add("obfuscation_control_chars")

    # Strip control characters for subsequent regex matching
    cleaned = CONTROL_CHARS_PATTERN.sub("", normalized)

    # 3. Obfuscation: base64 blobs near decode/execute
    if BASE64_OBFUSCATION_PATTERN_1.search(cleaned) or BASE64_OBFUSCATION_PATTERN_2.search(cleaned):
        score += 45
        reasons_set.add("obfuscation_base64")

    # 4. Override phrases
    for rule_id, pattern, weight in OVERRIDE_PATTERNS:
        if pattern.search(cleaned):
            score += weight
            reasons_set.add(rule_id)

    # 5. Exfiltration patterns
    for rule_id, pattern, weight in EXFILTRATION_PATTERNS:
        if pattern.search(cleaned):
            score += weight
            reasons_set.add(rule_id)

    # 6. Roleplay / Delimiter patterns
    for rule_id, pattern, weight in DELIMITER_PATTERNS:
        if pattern.search(cleaned):
            score += weight
            reasons_set.add(rule_id)

    # Determine risk level from cumulative score
    if score >= 40:
        risk = "high"
    elif score >= 20:
        risk = "medium"
    else:
        risk = "low"

    return InjectionResult(
        risk=risk,
        reasons=sorted(reasons_set),
        score=score,
    )
