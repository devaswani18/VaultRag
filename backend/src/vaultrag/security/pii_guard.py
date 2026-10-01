"""PII and Secret Guard: Pure Python, zero-dependency, linear-time sensitive data scanner.

Implements detectors for Aadhaar, PAN, Credit Cards, Indian Mobile numbers, Emails,
IFSC codes, AWS Access Keys, Generic Secrets, Private Keys, and JWT tokens.
Supports NFKC unicode normalisation, overlap resolution, and policy enforcement
(off, flag, redact, block).

Matched values are NEVER stored in findings or logged.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_CONFIDENCE_RANKS: dict[str, int] = {
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}


@dataclass(frozen=True)
class Finding:
    """Detected sensitive data span. NEVER stores the raw matched value."""

    type: str
    start: int
    end: int
    confidence: str


@dataclass(frozen=True)
class PolicyResult:
    """Outcome of applying a PII policy to text."""

    text: str
    findings_summary: dict[str, int]
    blocked: bool


# ------------------------------------------------------------------------------
# Checksum Algorithms (Pure Python, Linear Time)
# ------------------------------------------------------------------------------

# Verhoeff algorithm multiplication (d), permutation (p), and inverse tables
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)

_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def validate_verhoeff(num_str: str) -> bool:
    """Validate a digit string against the Verhoeff checksum algorithm."""
    c = 0
    for i, char in enumerate(reversed(num_str)):
        if not char.isdigit():
            return False
        val = int(char)
        p_val = _VERHOEFF_P[i % 8][val]
        c = _VERHOEFF_D[c][p_val]
    return c == 0


def generate_verhoeff(prefix: str) -> str:
    """Generate the full number including the Verhoeff checksum digit."""
    c = 0
    for i, char in enumerate(reversed(prefix)):
        val = int(char)
        p_val = _VERHOEFF_P[(i + 1) % 8][val]
        c = _VERHOEFF_D[c][p_val]
    check_digit = _VERHOEFF_INV[c]
    return prefix + str(check_digit)


def validate_luhn(num_str: str) -> bool:
    """Validate a digit string against the Luhn (Mod 10) algorithm."""
    digits = [int(c) for c in num_str if c.isdigit()]
    if not digits:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ------------------------------------------------------------------------------
# Precompiled Regexes (Strictly Linear Time, No Nested Quantifiers)
# ------------------------------------------------------------------------------

# Aadhaar: 12 digits, first digit 2-9, optional 4-4-4 spacing or hyphenation
# Must not be preceded or followed by alphanumeric characters (e.g. not part of ORD-...)
_AADHAAR_PATTERN = re.compile(r"(?<![A-Za-z0-9])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![A-Za-z0-9])")

# PAN: 5 letters (4th is holder type), 4 digits, 1 letter
_PAN_PATTERN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_VALID_PAN_HOLDER_TYPES = frozenset("ABCFGHLJPT")

# Credit Card: 13-19 digits, optional groupings with space or hyphen
_CC_PATTERN = re.compile(
    r"(?<!\d)(?:"
    r"\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,7}|"
    r"\d{4}[ -]\d{6}[ -]\d{4,5}|"
    r"\d{13,19}"
    r")(?!\d)"
)

# Indian Mobile: 10 digits starting 6-9, optional +91/91/0 prefix
_IN_MOBILE_PATTERN = re.compile(r"(?<!\d)(?:\+91[ -]?|91[ -]|0)?[6-9]\d{4}[ -]?\d{5}(?!\d)")
_MOBILE_KEYWORD_PATTERN = re.compile(r"\b(?:phone|mobile|contact|call|cell)\b", re.IGNORECASE)

# Email
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# IFSC: 4 uppercase letters, '0', 6 alphanumeric characters
_IFSC_PATTERN = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")

# AWS Access Key ID: AKIA or ASIA followed by 16 alphanumeric uppercase chars
_AWS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")

# Generic Secret: assignment like api_key|secret|token|password = "..."
_GENERIC_SECRET_PATTERN = re.compile(
    r"\b(?i:(?:api[_-]?key|secret|token|password|auth[_-]?token))\s*[:=]\s*[\"']?([A-Za-z0-9_\-.~!@#$%^&*+=]{8,})[\"']?"
)

# Private Key Header
_PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

# JWT: 3 base64url segments starting with eyJ
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")


# ------------------------------------------------------------------------------
# Normalization and Scanning API
# ------------------------------------------------------------------------------


def normalize(text: str) -> str:
    """Return NFKC-normalised text (standardises full-width characters and digits)."""
    return unicodedata.normalize("NFKC", text)


def _is_card_issuer_valid(clean_digits: str) -> bool:
    """Verify card issuer prefix."""
    length = len(clean_digits)
    if not (13 <= length <= 19):
        return False

    # Visa
    if clean_digits.startswith("4") and length in (13, 16, 19):
        return True
    # Mastercard
    if length == 16:
        prefix2 = int(clean_digits[:2])
        if 51 <= prefix2 <= 55:
            return True
        prefix4 = int(clean_digits[:4])
        if 2221 <= prefix4 <= 2720:
            return True
    # American Express
    if clean_digits[:2] in ("34", "37") and length == 15:
        return True
    # Discover
    if (clean_digits.startswith("6011") or clean_digits.startswith("65")) and length == 16:
        return True
    # JCB
    return bool(clean_digits.startswith("35") and 16 <= length <= 19)


def scan(text: str) -> list[Finding]:
    """Scan text for sensitive data and return non-overlapping findings.

    Normalises text first using NFKC.
    When candidate findings overlap, the higher confidence wins; on tie,
    the longer span wins; on tie, the earlier start position wins.
    """
    if not text:
        return []

    norm_text = normalize(text)
    raw_findings: list[Finding] = []

    # 1. Private Key
    for m in _PRIVATE_KEY_PATTERN.finditer(norm_text):
        raw_findings.append(Finding("PRIVATE_KEY", m.start(), m.end(), Confidence.HIGH))

    # 2. JWT Tokens
    for m in _JWT_PATTERN.finditer(norm_text):
        raw_findings.append(Finding("JWT", m.start(), m.end(), Confidence.HIGH))

    # 3. AWS Access Key
    for m in _AWS_KEY_PATTERN.finditer(norm_text):
        raw_findings.append(Finding("AWS_ACCESS_KEY", m.start(), m.end(), Confidence.HIGH))

    # 4. Generic Secret
    for m in _GENERIC_SECRET_PATTERN.finditer(norm_text):
        # We redact the entire assignment or the sensitive value span
        raw_findings.append(Finding("GENERIC_SECRET", m.start(), m.end(), Confidence.HIGH))

    # 5. Email
    for m in _EMAIL_PATTERN.finditer(norm_text):
        raw_findings.append(Finding("EMAIL", m.start(), m.end(), Confidence.HIGH))

    # 6. IFSC Code
    for m in _IFSC_PATTERN.finditer(norm_text):
        raw_findings.append(Finding("IFSC", m.start(), m.end(), Confidence.HIGH))

    # 7. PAN (Permanent Account Number)
    for m in _PAN_PATTERN.finditer(norm_text):
        pan_candidate = m.group(0)
        holder_type = pan_candidate[3]
        if holder_type in _VALID_PAN_HOLDER_TYPES:
            raw_findings.append(Finding("PAN", m.start(), m.end(), Confidence.HIGH))

    # 8. Aadhaar
    for m in _AADHAAR_PATTERN.finditer(norm_text):
        candidate = m.group(0)
        clean_digits = candidate.replace(" ", "").replace("-", "")
        if len(clean_digits) == 12 and validate_verhoeff(clean_digits):
            raw_findings.append(Finding("AADHAAR", m.start(), m.end(), Confidence.HIGH))

    # 9. Credit Card
    for m in _CC_PATTERN.finditer(norm_text):
        candidate = m.group(0)
        clean_digits = candidate.replace(" ", "").replace("-", "")
        if _is_card_issuer_valid(clean_digits) and validate_luhn(clean_digits):
            raw_findings.append(Finding("CREDIT_CARD", m.start(), m.end(), Confidence.HIGH))

    # 10. Indian Mobile
    for m in _IN_MOBILE_PATTERN.finditer(norm_text):
        start, end = m.start(), m.end()
        # Check nearby window for keyword (30 chars before and after)
        window_start = max(0, start - 30)
        window_end = min(len(norm_text), end + 30)
        context_window = norm_text[window_start:window_end]

        confidence = (
            Confidence.HIGH if _MOBILE_KEYWORD_PATTERN.search(context_window) else Confidence.MEDIUM
        )
        raw_findings.append(Finding("IN_MOBILE", start, end, confidence))

    if not raw_findings:
        return []

    # Sort candidates for greedy overlap resolution:
    # 1. Higher confidence rank first
    # 2. Longer span length first
    # 3. Earlier start first
    def _sort_key(f: Finding) -> tuple[int, int, int]:
        conf_rank = _CONFIDENCE_RANKS.get(f.confidence, 0)
        span_len = f.end - f.start
        return (-conf_rank, -span_len, f.start)

    sorted_candidates = sorted(raw_findings, key=_sort_key)

    chosen: list[Finding] = []
    for cand in sorted_candidates:
        # Check if candidate overlaps with any already chosen finding
        overlaps = False
        for c in chosen:
            if not (cand.end <= c.start or cand.start >= c.end):
                overlaps = True
                break
        if not overlaps:
            chosen.append(cand)

    # Return selected findings sorted by character start position
    return sorted(chosen, key=lambda f: f.start)


def apply_policy(text: str, mode: str = "redact") -> PolicyResult:
    """Apply PII policy to text.

    Modes:
      - 'off': Passthrough. Text is unchanged, findings_summary is empty.
      - 'flag': Text is unchanged, findings_summary contains counts of detected types.
      - 'redact': Replaces detected spans with tokens like [AADHAAR_REDACTED].
      - 'block': Returns blocked=True if any finding of confidence >= medium exists.

    NEVER logs or stores matched values.
    """
    clean_mode = (mode or "off").strip().lower()
    if clean_mode not in ("off", "flag", "redact", "block"):
        clean_mode = "redact"

    if clean_mode == "off" or not text:
        return PolicyResult(text=text, findings_summary={}, blocked=False)

    norm_text = normalize(text)
    findings = scan(norm_text)

    # Build summary (type -> count)
    summary: dict[str, int] = {}
    for f in findings:
        summary[f.type] = summary.get(f.type, 0) + 1

    if clean_mode == "flag":
        return PolicyResult(text=norm_text, findings_summary=summary, blocked=False)

    if clean_mode == "block":
        # Block when any finding of confidence >= medium is present
        is_blocked = any(
            _CONFIDENCE_RANKS.get(f.confidence, 0) >= _CONFIDENCE_RANKS[Confidence.MEDIUM]
            for f in findings
        )
        return PolicyResult(text=norm_text, findings_summary=summary, blocked=is_blocked)

    # mode == 'redact'
    # Replace spans from right to left so indices remain valid
    chars = list(norm_text)
    for f in reversed(findings):
        token = f"[{f.type}_REDACTED]"
        chars[f.start : f.end] = list(token)

    redacted_text = "".join(chars)
    return PolicyResult(text=redacted_text, findings_summary=summary, blocked=False)
