"""Tests for Evaluation Harness and Leak Detection Gates.

Mutation tests proving non-zero exit and leak detection on:
- Broken ACL filter (exposes manager docs to non-manager roles)
- Broken semantic cache scope key (leaks manager cache to intern)
- Omitted PII hook (leaves raw test PAN / Card in chunks)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from qdrant_client import models

# Ensure repo root is available in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from eval.run_eval import main, run_benchmark  # noqa: E402


class TestEvalHarness:
    """Test suite verifying evaluation benchmark runner and hard security gate mutations."""

    def test_eval_clean_run_passes_all_hard_gates(self) -> None:
        """A normal clean mock benchmark run must pass all 5 hard security gates."""
        summary, results = run_benchmark(mode="mock", seed=42)

        assert len(results) == 40
        assert summary.hard_gates_passed is True
        assert summary.acl_leaks == 0
        assert summary.cross_tenant_leaks == 0
        assert summary.pii_leaks == 0
        assert summary.cache_leaks == 0
        assert summary.injection_followed == 0

    def test_broken_acl_filter_mutation_triggers_leak_detection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Mutating the ACL filter to drop role checks must fail hard gates with acl_leaks > 0."""

        def leaky_build_filter(ctx: Any) -> models.Filter:
            # Flawed filter: only checks tenant_id, dropping all role/visibility restrictions
            return models.Filter(
                must=[
                    models.FieldCondition(
                        key="tenant_id",
                        match=models.MatchValue(value=ctx.tenant_id),
                    )
                ]
            )

        monkeypatch.setattr("vaultrag.security.acl.build_filter", leaky_build_filter)
        monkeypatch.setattr("vaultrag.rag.retrieve.build_filter", leaky_build_filter)

        summary, results = run_benchmark(
            mode="mock", only_category="role_restricted_denied", seed=42
        )

        assert summary.acl_leaks > 0, "Broken ACL filter must cause acl_leaks > 0"
        assert summary.hard_gates_passed is False, "Hard gates must fail when ACL leaks occur"
        assert summary.overall_passed is False

    def test_broken_cache_scope_key_mutation_triggers_leak_detection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Mutating cache scope_key to a constant string must leak manager cached answers to intern."""

        def unscoped_scope_key(ctx: Any) -> str:
            # Flawed scope: static hash across all roles in tenant
            return f"static-unscoped-cache-key-{ctx.tenant_id}"

        monkeypatch.setattr("vaultrag.rag.semantic_cache.compute_scope_key", unscoped_scope_key)

        summary, results = run_benchmark(mode="mock", only_category="cache_scope_probe", seed=42)

        assert summary.cache_leaks > 0, "Unscoped cache must cause cache_leaks > 0 for intern probe"
        assert summary.hard_gates_passed is False
        assert summary.overall_passed is False

    def test_omitted_pii_hook_mutation_triggers_leak_detection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Mutating ingestion hooks to omit PIIHook must cause raw PII leak detection."""

        def broken_hooks() -> list[Any]:
            # Flawed pipeline: omits PIIHook entirely
            from vaultrag.ingest.hooks.injection_hook import InjectionHook

            return [InjectionHook()]

        monkeypatch.setattr("vaultrag.ingest.pipeline.get_default_hooks", broken_hooks)
        monkeypatch.setattr("vaultrag.ingest.handler.get_default_hooks", broken_hooks)

        summary, results = run_benchmark(mode="mock", only_category="pii_probe", seed=42)

        assert summary.pii_leaks > 0, (
            "Omitted PII hook must leave raw PII in chunks and cause pii_leaks > 0"
        )
        assert summary.hard_gates_passed is False
        assert summary.overall_passed is False

    def test_eval_cli_exits_nonzero_on_hard_gate_violation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The CLI main() entrypoint must return non-zero exit code 1 when hard gates are violated."""

        def leaky_build_filter(ctx: Any) -> models.Filter:
            return models.Filter(
                must=[
                    models.FieldCondition(
                        key="tenant_id",
                        match=models.MatchValue(value=ctx.tenant_id),
                    )
                ]
            )

        monkeypatch.setattr("vaultrag.security.acl.build_filter", leaky_build_filter)
        monkeypatch.setattr("vaultrag.rag.retrieve.build_filter", leaky_build_filter)

        test_argv = ["run_eval.py", "--mode", "mock", "--only", "role_restricted_denied"]
        with patch.object(sys, "argv", test_argv):
            exit_code = main()
            assert exit_code == 1, "main() must exit with code 1 when hard gate leaks occur"
