#!/usr/bin/env python3
"""Run evaluation of prompt injection detection heuristics against eval/attack_set.yaml."""

from __future__ import annotations

import sys
from pathlib import Path

# Locate root directory containing eval/attack_set.yaml and backend/src
candidate_roots = [
    Path(__file__).resolve().parent.parent,
    Path(__file__).resolve().parent.parent.parent,
]
root_dir = next(
    (p for p in candidate_roots if (p / "eval" / "attack_set.yaml").exists()),
    candidate_roots[0],
)
backend_src = root_dir / "backend" / "src"
if str(backend_src) not in sys.path:
    sys.path.insert(0, str(backend_src))

import yaml
from vaultrag.security.injection_guard import scan_text


def run_evaluation() -> tuple[float, float]:
    dataset_path = root_dir / "eval" / "attack_set.yaml"
    if not dataset_path.exists():
        print(f"Error: dataset file not found at {dataset_path}")
        sys.exit(1)

    with open(dataset_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    samples = data.get("samples", [])
    if not samples:
        print("Error: No samples found in attack_set.yaml")
        sys.exit(1)

    total_attacks = 0
    detected_attacks = 0
    total_benign = 0
    false_positives = 0

    print("=" * 80)
    print(
        f"{'ID':<15} | {'CATEGORY':<16} | {'EXP':<6} | {'ACTUAL':<6} | {'SCORE':<5} | {'MATCH':<5}"
    )
    print("-" * 80)

    for sample in samples:
        sample_id = sample.get("id", "unknown")
        category = sample.get("category", "unknown")
        is_attack = bool(sample.get("is_attack", False))
        expected_risk = sample.get("expected_risk", "low")
        text = sample.get("text", "")

        result = scan_text(text)
        is_high = result.risk == "high"

        if is_attack:
            total_attacks += 1
            if is_high:
                detected_attacks += 1
        else:
            total_benign += 1
            if is_high:
                false_positives += 1

        matches = result.risk == expected_risk
        match_str = "OK" if matches else "DIFF"
        print(
            f"{sample_id:<15} | {category:<16} | {expected_risk:<6} | "
            f"{result.risk:<6} | {result.score:<5} | {match_str}"
        )

    detection_rate = (
        (detected_attacks / total_attacks * 100) if total_attacks > 0 else 0.0
    )
    fp_rate = (false_positives / total_benign * 100) if total_benign > 0 else 0.0

    print("=" * 80)
    print("EVALUATION SUMMARY:")
    print(f"  Total Samples Evaluated : {len(samples)}")
    print(f"  Total Attacks Evaluated : {total_attacks}")
    print(
        f"  Attacks Detected (High) : {detected_attacks}/{total_attacks} ({detection_rate:.1f}%)"
    )
    print(f"  Total Benign Evaluated  : {total_benign}")
    print(
        f"  Benign False Positives  : {false_positives}/{total_benign} ({fp_rate:.1f}%)"
    )
    print("=" * 80)

    # Documented benchmarks: detection rate >= 95%, false-positive rate <= 5%
    if detection_rate >= 95.0 and fp_rate <= 5.0:
        print("[PASS] Benchmark targets met (Detection >= 95%, False-Positive <= 5%).")
    else:
        print("[FAIL] Benchmark targets NOT met.")
        sys.exit(1)

    return detection_rate, fp_rate


if __name__ == "__main__":
    run_evaluation()
