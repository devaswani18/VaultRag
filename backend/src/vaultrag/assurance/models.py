"""Data models for the Assurance Center (Self-Test & Continuous Security)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class CheckResult:
    """Outcome of an individual security, compliance, or posture check."""

    id: str  # e.g. "I1", "A4", "D1", "C2"
    group: str  # e.g. "Isolation", "Access Control", "Data Protection", etc.
    name: str  # Human-readable title
    severity: str  # "critical" | "high" | "medium" | "low" | "warning"
    passed: bool  # True if check succeeded (or warning acknowledged)
    expected: str  # Plain English description of expected outcome
    actual: str  # Plain English description of observed outcome
    detail: str  # Safe technical detail (NO synthetic PII, tokens or raw secrets)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MatrixCell:
    """Represents one cell in the 6x5 Access Matrix."""

    canary: str  # "C1", "C2", "C3", "C4", "C5", "C6"
    principal: str  # "A-admin", "A-manager", "A-employee", "A-intern", "B-admin"
    expected_allowed: bool
    actually_allowed: bool
    state: str  # "allowed" | "blocked" | "leak" | "missing"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AssuranceReport:
    """Signed, verifiable attestation of tenant isolation, ACLs, and guardrails."""

    run_id: str
    tenant_id: str
    ts: str
    version: int
    simulated: bool
    simulated_bug: str | None
    summary: dict[str, int]  # {"passed": int, "total": int, "leaks": int, "missing": int}
    matrix: list[MatrixCell]
    checks: list[CheckResult]
    report_sha256: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "tenant_id": self.tenant_id,
            "ts": self.ts,
            "version": self.version,
            "simulated": self.simulated,
            "simulated_bug": self.simulated_bug,
            "summary": dict(self.summary),
            "matrix": [c.to_dict() for c in self.matrix],
            "checks": [c.to_dict() for c in self.checks],
            "report_sha256": self.report_sha256,
            "signature": self.signature,
        }
