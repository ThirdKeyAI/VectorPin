# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Migration: the opt-in LegacyV1Verifier must verify v1 test vectors.

This proves the v1 → v2 wire-format break does not orphan
historical pins. Production verifiers default to strict v2; operators
running a migration can opt in to legacy mode and continue verifying
v1 corpora until the re-pin pass is complete.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import numpy as np
import pytest

from vectorpin import LegacyV1Verifier, Verifier, VerifyError

V1_TESTVECTORS = Path(__file__).resolve().parent.parent / "testvectors" / "v1.json"


def _b64dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@pytest.fixture(scope="module")
def v1_corpus() -> dict:
    if not V1_TESTVECTORS.exists():
        pytest.skip("testvectors/v1.json not present")
    return json.loads(V1_TESTVECTORS.read_text())


def test_legacy_verifier_validates_every_v1_fixture(v1_corpus: dict):
    """Every entry in testvectors/v1.json verifies under LegacyV1Verifier."""
    pub = _b64dec(v1_corpus["public_key_b64"])
    verifier = LegacyV1Verifier({v1_corpus["key_id"]: pub})

    for fixture in v1_corpus["fixtures"]:
        pin = LegacyV1Verifier.parse_pin(fixture["expected"]["pin_json"])
        # Pure signature check (the v1 vector_b64 lets us go further if
        # we want, but the signature alone is the legacy proof).
        result = verifier.verify(pin)
        assert result.ok, (
            f"{fixture['name']}: expected OK, got "
            f"{result.error.value} ({result.detail})"
        )


def test_legacy_verifier_v1_full_check_with_vector(v1_corpus: dict):
    """Fully verify a v1 fixture including the vector — proves the v1
    canonical bytes path is byte-for-byte equivalent to the original
    v1 implementation."""
    pub = _b64dec(v1_corpus["public_key_b64"])
    verifier = LegacyV1Verifier({v1_corpus["key_id"]: pub})

    fixture = v1_corpus["fixtures"][0]
    pin = LegacyV1Verifier.parse_pin(fixture["expected"]["pin_json"])
    vec_bytes = _b64dec(fixture["input"]["vector_b64"])
    dtype = "<f4" if fixture["input"]["vec_dtype"] == "f32" else "<f8"
    vec = np.frombuffer(vec_bytes, dtype=dtype)

    result = verifier.verify(
        pin,
        source=fixture["input"]["source"],
        vector=vec,
        expected_model=fixture["input"]["model"],
    )
    assert result.ok


def test_strict_v2_verifier_rejects_v1_pin(v1_corpus: dict):
    """A default (strict) v2 verifier MUST refuse v1 pins."""
    pub = _b64dec(v1_corpus["public_key_b64"])
    verifier = Verifier({v1_corpus["key_id"]: pub})

    fixture = v1_corpus["fixtures"][0]
    pin = LegacyV1Verifier.parse_pin(fixture["expected"]["pin_json"])
    result = verifier.verify(pin)
    assert not result.ok
    assert result.error is VerifyError.UNSUPPORTED_VERSION


def test_legacy_verifier_still_accepts_v2_pins(v1_corpus: dict):
    """A LegacyV1Verifier accepts BOTH v1 and v2 pins so a migration
    window can run mixed traffic from a single registry."""
    from vectorpin import Signer

    signer = Signer.generate(key_id="v2-signer")
    pub = signer.public_key_bytes()
    verifier = LegacyV1Verifier({"v2-signer": pub})

    vec = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    pin = signer.pin(source="hi", model="m", vector=vec)
    assert pin.header.v == 2
    assert verifier.verify(pin)
