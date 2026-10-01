"""Unit tests for PII and Secret Guard (pii_guard.py)."""

from __future__ import annotations

import time

import pytest

from vaultrag.security.pii_guard import (
    apply_policy,
    generate_verhoeff,
    normalize,
    scan,
    validate_luhn,
    validate_verhoeff,
)


def _make_valid_aadhaar(prefix_11: str = "23456789012") -> str:
    """Generate a valid 12-digit Aadhaar number using Verhoeff checksum."""
    return generate_verhoeff(prefix_11)


class TestChecksumAlgorithms:
    def test_verhoeff_valid_and_invalid(self) -> None:
        valid_aadhaar = _make_valid_aadhaar("98765432109")
        assert validate_verhoeff(valid_aadhaar) is True

        # Invalidate checksum digit
        last_digit = int(valid_aadhaar[-1])
        corrupted = valid_aadhaar[:-1] + str((last_digit + 1) % 10)
        assert validate_verhoeff(corrupted) is False

    def test_luhn_valid_and_invalid(self) -> None:
        # Public Visa test card
        assert validate_luhn("4111111111111111") is True
        assert validate_luhn("4111 1111 1111 1111".replace(" ", "")) is True

        # Mutate check digit
        assert validate_luhn("4111111111111112") is False


class TestDetectorsTableDriven:
    @pytest.mark.parametrize(
        ("text", "expected_type", "should_detect"),
        [
            # AADHAAR
            (_make_valid_aadhaar("34567890123"), "AADHAAR", True),
            (
                f"{_make_valid_aadhaar('23456789012')[:4]} {_make_valid_aadhaar('23456789012')[4:8]} {_make_valid_aadhaar('23456789012')[8:]}",
                "AADHAAR",
                True,
            ),
            ("123456789012", "AADHAAR", False),  # Starts with 1 (invalid first digit)
            ("023456789012", "AADHAAR", False),  # Starts with 0
            ("2345678901234", "AADHAAR", False),  # 13 digits (longer digit run)
            ("170987654321", "AADHAAR", False),  # Timestamp starting with 1
            ("1790871616834", "AADHAAR", False),  # 13-digit Unix timestamp
            ("ORD-234567890120", "AADHAAR", False),  # Verhoeff invalid 12-digit order number
            ("234567890120", "AADHAAR", False),  # 12 digits, Verhoeff invalid
            # PAN
            ("ABCPE1234F", "PAN", True),  # P is Individual (valid)
            ("XYZPA9876Q", "PAN", True),  # P is Individual (valid)
            ("ABCDE1234", "PAN", False),  # Too short
            ("ABCDZ1234F", "PAN", False),  # Z is not a valid PAN holder type
            ("abcde1234f", "PAN", False),  # Lowercase (PAN is uppercase)
            # CREDIT_CARD
            ("4111 1111 1111 1111", "CREDIT_CARD", True),  # Visa
            ("4111111111111111", "CREDIT_CARD", True),
            ("4111 1111 1111 1112", "CREDIT_CARD", False),  # Invalid Luhn
            ("1111 2222 3333 4444", "CREDIT_CARD", False),  # Invalid issuer prefix
            # IN_MOBILE
            ("Call me at 9876543210 please", "IN_MOBILE", True),
            ("+91 9876543210", "IN_MOBILE", True),
            ("09876543210", "IN_MOBILE", True),
            ("1234567890", "IN_MOBILE", False),  # Starts with 1
            ("987654321012", "IN_MOBILE", False),  # Part of longer digit run
            # EMAIL
            ("user.test@example.com", "EMAIL", True),
            ("invalid-email@", "EMAIL", False),
            ("@example.com", "EMAIL", False),
            # IFSC
            ("HDFC0001234", "IFSC", True),
            ("SBIN0000001", "IFSC", True),
            ("HDFC1001234", "IFSC", False),  # 5th char must be 0
            # AWS_ACCESS_KEY
            ("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY", True),
            ("ASIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY", True),
            ("BKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY", False),
            # GENERIC_SECRET
            ('api_key = "super_secret_token_12345"', "GENERIC_SECRET", True),
            ("password: 'MySecretPassword123!'", "GENERIC_SECRET", True),
            ("token=9988776655443322", "GENERIC_SECRET", True),
            # PRIVATE_KEY
            ("-----BEGIN RSA PRIVATE KEY-----", "PRIVATE_KEY", True),
            ("-----BEGIN EC PRIVATE KEY-----", "PRIVATE_KEY", True),
            # JWT
            (
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozS6-V2m_B_sQ12345",  # gitleaks:allow
                "JWT",
                True,
            ),
        ],
    )
    def test_detector_samples(self, text: str, expected_type: str, should_detect: bool) -> None:
        findings = scan(text)
        types = [f.type for f in findings]
        if should_detect:
            assert expected_type in types, f"Expected {expected_type} in {types} for text: {text}"
        else:
            assert expected_type not in types, f"Did NOT expect {expected_type} for text: {text}"

    def test_mobile_confidence_keyword_boost(self) -> None:
        # Without keyword -> medium confidence
        plain = "My number is 9876543210 for reference."
        findings_plain = scan(plain)
        assert len(findings_plain) == 1
        assert findings_plain[0].confidence == "medium"

        # With keyword -> high confidence
        with_kw = "Please contact me on 9876543210 anytime."
        findings_kw = scan(with_kw)
        assert len(findings_kw) == 1
        assert findings_kw[0].confidence == "high"


class TestUnicodeNormalization:
    def test_full_width_digits_detected(self) -> None:
        # Full-width digits for a valid Aadhaar
        base_aadhaar = _make_valid_aadhaar("23456789012")
        # Convert each ascii digit to full-width unicode (ord + 0xFEE0)
        full_width_aadhaar = "".join(chr(ord(c) + 0xFEE0) for c in base_aadhaar)

        norm = normalize(full_width_aadhaar)
        assert norm == base_aadhaar

        findings = scan(full_width_aadhaar)
        assert len(findings) == 1
        assert findings[0].type == "AADHAAR"


class TestPolicyApplication:
    def test_redact_mode_masks_values_and_preserves_surrounding_text(self) -> None:
        valid_aadhaar = _make_valid_aadhaar("23456789012")
        text = f"Citizen Aadhaar is {valid_aadhaar} and email is test@corp.com."
        result = apply_policy(text, mode="redact")

        assert result.blocked is False
        assert valid_aadhaar not in result.text
        assert "test@corp.com" not in result.text
        assert "[AADHAAR_REDACTED]" in result.text
        assert "[EMAIL_REDACTED]" in result.text
        assert result.text == "Citizen Aadhaar is [AADHAAR_REDACTED] and email is [EMAIL_REDACTED]."
        assert result.findings_summary == {"AADHAAR": 1, "EMAIL": 1}

    def test_flag_mode_keeps_text_unchanged(self) -> None:
        valid_aadhaar = _make_valid_aadhaar("23456789012")
        text = f"User card is 4111 1111 1111 1111 and Aadhaar is {valid_aadhaar}."
        result = apply_policy(text, mode="flag")

        assert result.blocked is False
        assert result.text == text
        assert result.findings_summary["CREDIT_CARD"] == 1
        assert result.findings_summary["AADHAAR"] == 1

    def test_block_mode_blocks_when_medium_or_high_present(self) -> None:
        valid_pan = "ABCPE1234F"
        text = f"Confidential PAN: {valid_pan}"
        result = apply_policy(text, mode="block")

        assert result.blocked is True
        assert result.findings_summary["PAN"] == 1

    def test_off_mode_passthrough(self) -> None:
        text = "My email is secret@acme.com and card is 4111 1111 1111 1111"
        result = apply_policy(text, mode="off")

        assert result.blocked is False
        assert result.text == text
        assert result.findings_summary == {}


class TestPerformance:
    def test_adversarial_1mb_scan_under_one_second(self) -> None:
        # Construct 1 MB adversarial string with long digit runs and repeated "a@"
        chunk_pattern = "9" * 500 + " " + "a@" * 250 + "\n"
        repetitions = (1024 * 1024) // len(chunk_pattern) + 1
        adversarial_text = chunk_pattern * repetitions
        assert len(adversarial_text.encode("utf-8")) >= 1024 * 1024

        start = time.perf_counter()
        findings = scan(adversarial_text)
        elapsed = time.perf_counter() - start

        assert elapsed < 1.0, f"Adversarial scan took {elapsed:.3f}s (must be < 1.0s)"
        assert isinstance(findings, list)
