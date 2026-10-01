#!/usr/bin/env python3
"""Calibrate retrieval gate threshold (min_retrieval_score) using eval/golden_set.yaml."""

from __future__ import annotations

import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# Locate repository root
candidate_roots = [
    Path(__file__).resolve().parent.parent,
    Path(__file__).resolve().parent.parent.parent,
]
root_dir = next(
    (p for p in candidate_roots if (p / "eval" / "golden_set.yaml").exists()),
    candidate_roots[0],
)
backend_src = root_dir / "backend" / "src"
if str(backend_src) not in sys.path:
    sys.path.insert(0, str(backend_src))

import yaml

TOKEN_RE = re.compile(r"\b[a-zA-Z0-9_-]+\b")


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in TOKEN_RE.findall(text)]


def _cosine_similarity(vec1: Counter[str], vec2: Counter[str]) -> float:
    intersection = set(vec1.keys()) & set(vec2.keys())
    dot_product = sum(vec1[x] * vec2[x] for x in intersection)

    norm1 = math.sqrt(sum(v * v for v in vec1.values()))
    norm2 = math.sqrt(sum(v * v for v in vec2.values()))

    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0
    return dot_product / (norm1 * norm2)


def compute_best_score(question: str, corpus_chunks: list[str]) -> float:
    """Compute best retrieval similarity score for a question against corpus chunks."""
    q_tokens = _tokenize(question)
    q_vec = Counter(q_tokens)
    best = 0.0
    for chunk in corpus_chunks:
        c_tokens = _tokenize(chunk)
        c_vec = Counter(c_tokens)
        sim = _cosine_similarity(q_vec, c_vec)
        best = max(best, sim)
    return best


def run_calibration() -> float:
    golden_path = root_dir / "eval" / "golden_set.yaml"
    if not golden_path.exists():
        print(f"Error: {golden_path} not found")
        sys.exit(1)

    with open(golden_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    # 1. Load corpus chunks
    corpus_files = data.get("corpus", [])
    chunks: list[str] = []
    for rel_path in corpus_files:
        full_path = root_dir / rel_path
        if full_path.exists():
            text = full_path.read_text(encoding="utf-8")
            # Break by paragraphs
            paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 30]
            chunks.extend(paragraphs)

    if not chunks:
        print("Error: No corpus chunks loaded")
        sys.exit(1)

    # 2. Evaluate questions
    questions = data.get("questions", [])
    answerable_scores: list[float] = []
    unanswerable_scores: list[float] = []

    print("=" * 80)
    print(f"{'ID':<10} | {'ANSWERABLE':<12} | {'BEST SCORE':<12} | QUESTION")
    print("-" * 80)

    results: list[dict[str, Any]] = []
    for q in questions:
        qid = q.get("id", "")
        qtext = q.get("question", "")
        is_ans = bool(q.get("answerable", False))
        score = compute_best_score(qtext, chunks)

        if is_ans:
            answerable_scores.append(score)
        else:
            unanswerable_scores.append(score)

        results.append({"id": qid, "is_ans": is_ans, "score": score, "text": qtext})
        ans_str = "YES" if is_ans else "NO"
        print(f"{qid:<10} | {ans_str:<12} | {score:<12.4f} | {qtext[:42]}...")

    # 3. Compute score distributions
    ans_min = min(answerable_scores) if answerable_scores else 0.0
    ans_max = max(answerable_scores) if answerable_scores else 0.0
    ans_mean = sum(answerable_scores) / max(len(answerable_scores), 1)

    unans_min = min(unanswerable_scores) if unanswerable_scores else 0.0
    unans_max = max(unanswerable_scores) if unanswerable_scores else 0.0
    unans_mean = sum(unanswerable_scores) / max(len(unanswerable_scores), 1)

    print("=" * 80)
    print("SCORE DISTRIBUTIONS:")
    print(
        f"  Answerable (In-Doc)     : Min={ans_min:.4f}, Mean={ans_mean:.4f}, Max={ans_max:.4f}"
    )
    print(
        f"  Unanswerable (Out-of-Doc): Min={unans_min:.4f}, "
        f"Mean={unans_mean:.4f}, Max={unans_max:.4f}"
    )

    # 4. Grid search for threshold maximizing balanced classification accuracy
    best_threshold = 0.35
    best_acc = -1.0

    # Search candidates between 0.15 and 0.55
    for t_int in range(15, 56):
        thresh = t_int / 100.0
        tp = sum(1 for s in answerable_scores if s >= thresh)
        fn = sum(1 for s in answerable_scores if s < thresh)
        tn = sum(1 for s in unanswerable_scores if s < thresh)
        fp = sum(1 for s in unanswerable_scores if s >= thresh)

        total = tp + fn + tn + fp
        acc = (tp + tn) / total if total > 0 else 0.0

        if acc > best_acc or (
            acc == best_acc and abs(thresh - 0.35) < abs(best_threshold - 0.35)
        ):
            best_acc = acc
            best_threshold = thresh

    print("-" * 80)
    print(
        f"OPTIMAL THRESHOLD FOUND : {best_threshold:.2f} "
        f"(Balanced Accuracy: {best_acc * 100:.1f}%)"
    )
    print(f"RECOMMENDED min_retrieval_score: {best_threshold:.2f}")
    print("=" * 80)

    return best_threshold


if __name__ == "__main__":
    run_calibration()
