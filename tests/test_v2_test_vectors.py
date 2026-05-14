# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Load testvectors/v2.json and testvectors/negative_v2.json and check.

This is the cross-language compat anchor: the same test ports verbatim
to Rust and TypeScript implementations, asserting that each language
produces identical canonical bytes and verification verdicts.

If this file is updated, the Rust + TS test fixtures MUST be re-run too.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import numpy as np
import pytest

from vectorpin import DOMAIN_TAG, Pin, Verifier, VerifyError

V2_VECTORS = Path(__file__).resolve().parent.parent / "testvectors" / "v2.json"
NEG_V2_VECTORS = Path(__file__).resolve().parent.parent / "testvectors" / "negative_v2.json"


def _b64dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@pytest.fixture(scope="module")
def v2_corpus() -> dict:
    if not V2_VECTORS.exists():
        pytest.skip("testvectors/v2.json not present; run scripts/generate_test_vectors.py")
    return json.loads(V2_VECTORS.read_text())


@pytest.fixture(scope="module")
def neg_corpus() -> dict:
    if not NEG_V2_VECTORS.exists():
        pytest.skip("testvectors/negative_v2.json not present")
    return json.loads(NEG_V2_VECTORS.read_text())


# ---- positive ----


def test_corpus_metadata_is_consistent(v2_corpus: dict):
    assert v2_corpus["version"] == 2
    assert _b64dec(v2_corpus["domain_tag_b64"]) == DOMAIN_TAG


def test_each_positive_fixture_verifies(v2_corpus: dict):
    pub = _b64dec(v2_corpus["public_key_b64"])
    verifier = Verifier({v2_corpus["key_id"]: pub})

    for fixture in v2_corpus["fixtures"]:
        pin = Pin.from_json(fixture["pin_json"])
        result = verifier.verify(pin)
        assert result.ok, (
            f"{fixture['name']} sig-only: expected OK, got "
            f"{result.error.value}: {result.detail}"
        )


def test_each_positive_fixture_full_verify_with_vector(v2_corpus: dict):
    """End-to-end: verify signature + supplied source + supplied vector."""
    pub = _b64dec(v2_corpus["public_key_b64"])
    verifier = Verifier({v2_corpus["key_id"]: pub})

    for fixture in v2_corpus["fixtures"]:
        pin = Pin.from_json(fixture["pin_json"])
        inp = fixture["input"]
        vec_bytes = _b64dec(inp["vec_b64"])
        dtype = "<f4" if inp["vec_dtype"] == "f32" else "<f8"
        vec = np.frombuffer(vec_bytes, dtype=dtype)
        result = verifier.verify(
            pin,
            source=inp["source"],
            vector=vec,
            expected_model=inp["model"],
        )
        assert result.ok, (
            f"{fixture['name']} full verify: expected OK, got "
            f"{result.error.value}: {result.detail}"
        )


def test_canonical_bytes_match_expected(v2_corpus: dict):
    """The canonical_bytes_b64 we emit must round-trip stably."""
    for fixture in v2_corpus["fixtures"]:
        pin = Pin.from_json(fixture["pin_json"])
        expected = _b64dec(fixture["expected_canonical_bytes_b64"])
        actual = pin.header.canonicalize()
        assert actual == expected, fixture["name"]
        # And the canonical bytes start with the domain tag.
        assert actual.startswith(DOMAIN_TAG)


# ---- negative ----


_FAIL_MAP = {
    "VECTOR_TAMPERED": VerifyError.VECTOR_TAMPERED,
    "SOURCE_MISMATCH": VerifyError.SOURCE_MISMATCH,
    "MODEL_MISMATCH": VerifyError.MODEL_MISMATCH,
    "SIGNATURE_INVALID": VerifyError.SIGNATURE_INVALID,
    "UNSUPPORTED_VERSION": VerifyError.UNSUPPORTED_VERSION,
    "UNKNOWN_KEY": VerifyError.UNKNOWN_KEY,
    "KEY_EXPIRED": VerifyError.KEY_EXPIRED,
    "PARSE_ERROR": VerifyError.PARSE_ERROR,
    "SHAPE_MISMATCH": VerifyError.SHAPE_MISMATCH,
    "RECORD_MISMATCH": VerifyError.RECORD_MISMATCH,
    "COLLECTION_MISMATCH": VerifyError.COLLECTION_MISMATCH,
    "TENANT_MISMATCH": VerifyError.TENANT_MISMATCH,
}


def _try_parse(pin_json: str) -> tuple[Pin | None, str | None]:
    """Return (pin, None) on parse success or (None, error_message) on failure."""
    try:
        return Pin.from_json(pin_json), None
    except (ValueError, json.JSONDecodeError) as e:
        return None, str(e)


def test_each_negative_fixture_fails_correctly(neg_corpus: dict):
    pub = _b64dec(neg_corpus["public_key_b64"])
    verifier = Verifier({neg_corpus["key_id"]: pub})

    for fixture in neg_corpus["fixtures"]:
        name = fixture["name"]
        expected_str = fixture["expected_failure"]
        expected_err = _FAIL_MAP[expected_str]

        # Some fixtures fail at parse, others at verify. We unify by
        # mapping parse failures to VerifyError.PARSE_ERROR.
        pin, parse_err = _try_parse(fixture["pin_json"])

        if parse_err is not None:
            # Distinguish a version-rejection at parse time (which
            # protocol-wise is UNSUPPORTED_VERSION) from other
            # structural failures (PARSE_ERROR). The spec leaves the
            # boundary up to the implementation; both error codes
            # are valid for "v not equal to my supported version".
            if "version" in parse_err.lower():
                actual_err = VerifyError.UNSUPPORTED_VERSION
            else:
                actual_err = VerifyError.PARSE_ERROR
        else:
            assert pin is not None
            # Build verify kwargs based on what the fixture supplies.
            kwargs: dict = {}
            if "tampered_source" in fixture:
                kwargs["source"] = fixture["tampered_source"]
            if "tampered_vec_b64" in fixture:
                vec_bytes = _b64dec(fixture["tampered_vec_b64"])
                dtype = "<f4" if fixture["vec_dtype"] == "f32" else "<f8"
                kwargs["vector"] = np.frombuffer(vec_bytes, dtype=dtype)
            if "nan_vec_b64" in fixture:
                vec_bytes = _b64dec(fixture["nan_vec_b64"])
                dtype = "<f4" if fixture["vec_dtype"] == "f32" else "<f8"
                kwargs["vector"] = np.frombuffer(vec_bytes, dtype=dtype)
            if "expected_model" in fixture:
                kwargs["expected_model"] = fixture["expected_model"]
            if "expected_record_id" in fixture:
                kwargs["expected_record_id"] = fixture["expected_record_id"]
            if "expected_collection_id" in fixture:
                kwargs["expected_collection_id"] = fixture["expected_collection_id"]
            if "expected_tenant_id" in fixture:
                kwargs["expected_tenant_id"] = fixture["expected_tenant_id"]

            result = verifier.verify(pin, **kwargs)
            assert not result.ok, f"{name}: expected failure but got OK"
            actual_err = result.error

        assert actual_err is expected_err, (
            f"{name}: expected {expected_str}, got {actual_err.value} "
            f"(parse_err={parse_err!r})"
        )
