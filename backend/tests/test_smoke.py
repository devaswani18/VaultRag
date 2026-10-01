"""Smoke tests for vaultrag package."""

import vaultrag


def test_version() -> None:
    """Assert package version is set properly."""
    assert vaultrag.__version__ == "0.1.0"
