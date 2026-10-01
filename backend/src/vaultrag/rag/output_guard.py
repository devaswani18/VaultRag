"""RAG output guard: validates LLM-generated answer before returning to the caller.

Verifies:
  1. Canary string has not leaked into the generated answer.
  2. Answer does not contain external URLs, domains, or markdown image/link exfiltration
     targets not present in the retrieved source chunks.
  3. Answer does not leak internal system prompt phrases (e.g. "retrieved_document",
     "untrusted reference data").
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from vaultrag.rag.retrieve import RetrievedChunk

logger = logging.getLogger(__name__)

SAFE_FALLBACK_ANSWER = (
    "I could not provide a verified answer based on the trusted document sources."
)

URL_REGEX = re.compile(r"(?i)\bhttps?://[^\s)\]\"'>]+")
MARKDOWN_LINK_REGEX = re.compile(r"(?i)(?:!\[[^\]]*\]|\[[^\]]*\])\((https?://[^\s)]+)\)")

SYSTEM_PROMPT_LEAK_PHRASES = [
    re.compile(r"(?i)\bretrieved_document\b"),
    re.compile(r"(?i)\buntrusted\s+reference\s+data\b"),
    re.compile(r"(?i)\bnever\s+follow\s+instructions\b"),
    re.compile(r"(?i)\bCANARY:\s*vr-\b"),
]


@dataclass(frozen=True)
class OutputCheckResult:
    """Result of output verification check."""

    ok: bool
    reasons: list[str] = field(default_factory=list)
    safe_answer: str = ""


def _extract_urls_and_domains(text: str) -> tuple[set[str], set[str]]:
    """Extract full URLs and netloc domains from text."""
    urls = set(URL_REGEX.findall(text))
    for m in MARKDOWN_LINK_REGEX.finditer(text):
        urls.add(m.group(1))

    domains: set[str] = set()
    for u in urls:
        try:
            parsed = urlparse(u)
            if parsed.netloc:
                domains.add(parsed.netloc.lower())
        except Exception:
            logger.debug("Failed to parse URL domain: %s", u)
            continue

    return urls, domains


def check_output(
    answer: str,
    chunks: list[RetrievedChunk],
    canary: str | None = None,
) -> OutputCheckResult:
    """Inspect answer and return safe fallback if any guard check fails."""
    if not answer:
        return OutputCheckResult(ok=True, reasons=[], safe_answer=answer)

    reasons_set: set[str] = set()

    # 1. Canary leak check
    if canary and canary in answer:
        reasons_set.add("canary_leak")

    # 2. System prompt leak check
    for phrase_pattern in SYSTEM_PROMPT_LEAK_PHRASES:
        if phrase_pattern.search(answer):
            reasons_set.add("system_prompt_leak")
            break

    # 3. Untrusted URL / Markdown Link / Exfiltration check
    ans_urls, ans_domains = _extract_urls_and_domains(answer)
    if ans_urls:
        # Collect trusted URLs and domains from retrieved chunks
        chunk_combined_text = "\n".join(c.text for c in chunks)
        _, trusted_domains = _extract_urls_and_domains(chunk_combined_text)

        # Check if any answer domain was NOT present in any chunk
        untrusted = [u for u in ans_urls if urlparse(u).netloc.lower() not in trusted_domains]
        if untrusted:
            reasons_set.add("untrusted_url")

    if reasons_set:
        reasons = sorted(reasons_set)
        logger.warning("Answer blocked by output guard: reasons=%s", reasons)
        return OutputCheckResult(
            ok=False,
            reasons=reasons,
            safe_answer=SAFE_FALLBACK_ANSWER,
        )

    return OutputCheckResult(
        ok=True,
        reasons=[],
        safe_answer=answer,
    )
