# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Protocol v2 canonicalization, signing, and parse-time guarantees.

These tests pin down the v2 wire-format break: domain tag, v / kid in
the signed bytes, strict NFC + control-char + bidi-override rejection,
strict timestamp regex, no unknown top-level fields, no non-string
extra values, NaN/Inf rejection at sign time, and §4.3 size limits.
"""

from __future__ import annotations

import base64
import json

import numpy as np
import pytest

from vectorpin import (
    DOMAIN_TAG,
    PROTOCOL_VERSION,
    Pin,
    PinHeader,
    Signer,
    Verifier,
    VerifyError,
)

# ---- fixtures ----


@pytest.fixture
def signer() -> Signer:
    return Signer.generate(key_id="prod-2026-05")


@pytest.fixture
def verifier(signer: Signer) -> Verifier:
    return Verifier({signer.key_id: signer.public_key()})


@pytest.fixture
def vector() -> np.ndarray:
    rng = np.random.default_rng(0)
    return rng.normal(0, 1, size=16).astype(np.float32)


# ---- domain tag ----


def test_protocol_version_is_2():
    assert PROTOCOL_VERSION == 2


def test_domain_tag_bytes():
    assert DOMAIN_TAG == b"vectorpin/v2\x00"


def test_signed_bytes_start_with_domain_tag(signer: Signer, vector: np.ndarray):
    pin = signer.pin(source="hello", model="m", vector=vector)
    canonical = pin.header.canonicalize()
    assert canonical.startswith(DOMAIN_TAG)
    # And the rest is JSON.
    body = canonical[len(DOMAIN_TAG):]
    decoded = json.loads(body)
    assert decoded["v"] == 2
    assert decoded["kid"] == "prod-2026-05"


# ---- v and kid bound to signature ----


def test_changing_v_breaks_signature(signer: Signer, verifier: Verifier, vector: np.ndarray):
    """Flipping `v` from 2 to anything else MUST break verification.

    This is the audit-finding fix: in v1, `v` was unsigned, so a
    downgrade-and-re-version attack was possible. v2 includes `v` in
    the canonical bytes; any change breaks the ed25519 signature.
    """
    pin = signer.pin(source="x", model="m", vector=vector)
    tampered_header = PinHeader(
        v=99,  # changed from 2
        kid=pin.header.kid,
        model=pin.header.model,
        source_hash=pin.header.source_hash,
        vec_hash=pin.header.vec_hash,
        vec_dtype=pin.header.vec_dtype,
        vec_dim=pin.header.vec_dim,
        ts=pin.header.ts,
    )
    tampered = Pin(header=tampered_header, sig=pin.sig)
    result = verifier.verify(tampered)
    assert not result.ok
    # The version filter fires first.
    assert result.error is VerifyError.UNSUPPORTED_VERSION


def test_changing_kid_breaks_signature(signer: Signer, vector: np.ndarray):
    """Re-attributing a pin to a different `kid` MUST break verification.

    The audit-finding fix for cross-key swap: in v1, `kid` was
    unsigned, so an attacker could lift (header, sig) and re-attribute
    it to a different producer. v2 binds `kid` to the signature.
    """
    pin = signer.pin(source="x", model="m", vector=vector)
    other_signer = Signer.generate(key_id="other-kid")
    swapped_header = PinHeader(
        v=pin.header.v,
        kid="other-kid",  # changed
        model=pin.header.model,
        source_hash=pin.header.source_hash,
        vec_hash=pin.header.vec_hash,
        vec_dtype=pin.header.vec_dtype,
        vec_dim=pin.header.vec_dim,
        ts=pin.header.ts,
    )
    swapped = Pin(header=swapped_header, sig=pin.sig)
    # Verifier knows both keys; the swap must still fail signature.
    verifier = Verifier(
        {
            "prod-2026-05": signer.public_key(),
            "other-kid": other_signer.public_key(),
        }
    )
    result = verifier.verify(swapped)
    assert not result.ok
    assert result.error is VerifyError.SIGNATURE_INVALID


# ---- NaN/Inf rejection at sign time ----


def test_nan_in_vector_rejected_at_sign_time(signer: Signer):
    vec = np.array([1.0, 2.0, float("nan"), 4.0], dtype=np.float32)
    with pytest.raises(ValueError, match="NaN or infinity"):
        signer.pin(source="x", model="m", vector=vec)


def test_positive_inf_in_vector_rejected_at_sign_time(signer: Signer):
    vec = np.array([1.0, 2.0, float("inf"), 4.0], dtype=np.float32)
    with pytest.raises(ValueError, match="NaN or infinity"):
        signer.pin(source="x", model="m", vector=vec)


def test_negative_inf_in_vector_rejected_at_sign_time(signer: Signer):
    vec = np.array([1.0, 2.0, float("-inf"), 4.0], dtype=np.float32)
    with pytest.raises(ValueError, match="NaN or infinity"):
        signer.pin(source="x", model="m", vector=vec)


def test_signed_negative_zero_accepted(signer: Signer, verifier: Verifier):
    """Spec §3.2: -0.0 and +0.0 are distinct and both valid."""
    vec_pos = np.array([0.0, 1.0], dtype=np.float32)
    vec_neg = np.array([-0.0, 1.0], dtype=np.float32)
    pin_pos = signer.pin(source="x", model="m", vector=vec_pos)
    pin_neg = signer.pin(source="x", model="m", vector=vec_neg)
    # Both verify against their own vectors.
    assert verifier.verify(pin_pos, vector=vec_pos)
    assert verifier.verify(pin_neg, vector=vec_neg)
    # And the hashes ARE different — +0.0 vs -0.0 has distinct bytes.
    assert pin_pos.header.vec_hash != pin_neg.header.vec_hash


# ---- NFC enforcement ----


def _valid_pin_dict(**overrides):
    d = {
        "v": PROTOCOL_VERSION,
        "kid": "k",
        "model": "m",
        "source_hash": "sha256:" + "0" * 64,
        "vec_hash": "sha256:" + "1" * 64,
        "vec_dtype": "f32",
        "vec_dim": 16,
        "ts": "2026-05-13T00:00:00Z",
        "sig": base64.urlsafe_b64encode(b"\x01" * 64).rstrip(b"=").decode("ascii"),
    }
    d.update(overrides)
    return d


def test_nfd_model_string_rejected_at_parse():
    """An NFD-form composed character must be rejected.

    'cafe' + U+0301 COMBINING ACUTE is the NFD form of 'café';
    'caf' + U+00E9 (precomposed) is the NFC form. The parser must
    reject NFD inputs.
    """
    nfd_cafe = "cafe\u0301"
    # Sanity: this string IS in NFD, not NFC.
    import unicodedata
    assert unicodedata.normalize("NFC", nfd_cafe) != nfd_cafe
    assert unicodedata.normalize("NFC", nfd_cafe) == "caf\u00e9"
    with pytest.raises(ValueError, match="NFC"):
        Pin.from_dict(_valid_pin_dict(model=nfd_cafe))


def test_nfd_kid_string_rejected_at_parse():
    nfd = "cafe\u0301"  # NFD form
    with pytest.raises(ValueError, match="NFC"):
        Pin.from_dict(_valid_pin_dict(kid=nfd))


def test_control_character_in_model_rejected():
    with pytest.raises(ValueError, match="control character"):
        Pin.from_dict(_valid_pin_dict(model="bad\x07name"))


def test_bidi_override_in_model_rejected():
    # U+202E RIGHT-TO-LEFT OVERRIDE
    with pytest.raises(ValueError, match="bidi"):
        Pin.from_dict(_valid_pin_dict(model="evil‮name"))


# ---- timestamp strictness ----


def test_ts_fractional_seconds_rejected():
    with pytest.raises(ValueError, match="ts"):
        Pin.from_dict(_valid_pin_dict(ts="2026-05-05T12:00:00.000Z"))


def test_ts_offset_rejected():
    with pytest.raises(ValueError, match="ts"):
        Pin.from_dict(_valid_pin_dict(ts="2026-05-05T12:00:00+00:00"))


def test_ts_lowercase_t_rejected():
    with pytest.raises(ValueError, match="ts"):
        Pin.from_dict(_valid_pin_dict(ts="2026-05-05t12:00:00Z"))


def test_ts_lowercase_z_rejected():
    with pytest.raises(ValueError, match="ts"):
        Pin.from_dict(_valid_pin_dict(ts="2026-05-05T12:00:00z"))


# ---- unknown top-level field ----


def test_unknown_top_level_field_rejected():
    bad = _valid_pin_dict()
    bad["sig2"] = "extra"
    with pytest.raises(ValueError, match="unknown top-level"):
        Pin.from_dict(bad)


# ---- non-string extra ----


def test_non_string_extra_value_rejected():
    with pytest.raises(ValueError, match="extra values"):
        Pin.from_dict(_valid_pin_dict(extra={"k": 42}))


def test_non_string_extra_value_list_rejected():
    with pytest.raises(ValueError, match="extra values"):
        Pin.from_dict(_valid_pin_dict(extra={"k": ["a", "b"]}))


# ---- size limits (§4.3) ----


def test_oversize_pin_json_rejected():
    """Spec §4.3: total pin JSON > 64 KiB MUST be rejected."""
    huge = '{"v":2,"junk":"' + ("a" * 70_000) + '"}'
    with pytest.raises(ValueError, match="too large"):
        Pin.from_json(huge)


def test_extra_entries_limit_enforced():
    """Spec §4.3: extra entry count limit is 32."""
    big_extra = {f"k{i}": "v" for i in range(33)}
    with pytest.raises(ValueError, match="32"):
        Pin.from_dict(_valid_pin_dict(extra=big_extra))


def test_extra_key_size_limit_enforced():
    """Spec §4.3: extra keys cap at 128 bytes."""
    long_key = "k" * 129
    with pytest.raises(ValueError, match="128"):
        Pin.from_dict(_valid_pin_dict(extra={long_key: "v"}))


def test_extra_value_size_limit_enforced():
    """Spec §4.3: extra values cap at 1 KiB."""
    long_val = "v" * 1025
    with pytest.raises(ValueError, match="1024"):
        Pin.from_dict(_valid_pin_dict(extra={"k": long_val}))


def test_vec_dim_at_limit_accepted():
    """Spec §4.3: vec_dim <= 2^20 is acceptable; > 2^20 rejected."""
    # The header isn't bound to a vector here; just round-trip a dict.
    pin = Pin.from_dict(_valid_pin_dict(vec_dim=1_048_576))
    assert pin.header.vec_dim == 1_048_576


def test_vec_dim_over_limit_rejected():
    with pytest.raises(ValueError, match="vec_dim"):
        Pin.from_dict(_valid_pin_dict(vec_dim=1_048_577))


# ---- end-to-end sign/verify ----


def test_v2_pin_signs_and_verifies(signer: Signer, verifier: Verifier, vector: np.ndarray):
    pin = signer.pin(source="hello", model="text-model", vector=vector)
    assert pin.header.v == 2
    result = verifier.verify(pin, source="hello", vector=vector)
    assert result.ok


def test_v2_pin_with_extra_includes_record_id(
    signer: Signer, verifier: Verifier, vector: np.ndarray
):
    pin = signer.pin(
        source="x",
        model="m",
        vector=vector,
        extra={"vectorpin.record_id": "rec-1"},
    )
    # Reserved keys round-trip and live in extra.
    assert pin.header.extra["vectorpin.record_id"] == "rec-1"
    # Untouched, verifies.
    assert verifier.verify(pin)
