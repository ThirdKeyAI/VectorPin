# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""End-to-end signer/verifier round trip tests.

These cover the headline guarantee: a Pin created by Signer for a
given (text, vector) verifies iff the verifier has the matching key
AND the text/vector haven't been touched.
"""

from __future__ import annotations

import numpy as np
import pytest

from vectorpin import Pin, Signer, Verifier, VerifyError


@pytest.fixture
def vector() -> np.ndarray:
    rng = np.random.default_rng(42)
    return rng.normal(0, 1, size=128).astype(np.float32)


@pytest.fixture
def signer() -> Signer:
    return Signer.generate(key_id="test-key-1")


@pytest.fixture
def verifier(signer: Signer) -> Verifier:
    return Verifier({signer.key_id: signer.public_key()})


def test_full_verification_passes(signer: Signer, verifier: Verifier, vector: np.ndarray):
    pin = signer.pin(source="hello world", model="m", vector=vector)
    result = verifier.verify(pin, source="hello world", vector=vector)
    assert result.ok
    assert result.error is VerifyError.OK


def test_signature_only_verification_passes(
    signer: Signer, verifier: Verifier, vector: np.ndarray
):
    pin = signer.pin(source="x", model="m", vector=vector)
    # Caller has no source/vector to compare against — verify signature alone.
    assert verifier.verify(pin)


def test_modified_vector_is_caught(signer: Signer, verifier: Verifier, vector: np.ndarray):
    pin = signer.pin(source="x", model="m", vector=vector)
    tampered = vector.copy()
    tampered[0] += 1e-5
    result = verifier.verify(pin, vector=tampered)
    assert not result.ok
    assert result.error is VerifyError.VECTOR_TAMPERED


def test_modified_source_is_caught(signer: Signer, verifier: Verifier, vector: np.ndarray):
    pin = signer.pin(source="hello", model="m", vector=vector)
    result = verifier.verify(pin, source="HELLO", vector=vector)
    assert not result.ok
    assert result.error is VerifyError.SOURCE_MISMATCH


def test_unknown_signing_key_is_caught(vector: np.ndarray):
    rogue = Signer.generate(key_id="rogue")
    pin = rogue.pin(source="x", model="m", vector=vector)
    verifier = Verifier({"prod": Signer.generate(key_id="prod").public_key()})
    result = verifier.verify(pin)
    assert not result.ok
    assert result.error is VerifyError.UNKNOWN_KEY


def test_re_signed_pin_with_wrong_kid_is_caught(verifier: Verifier, vector: np.ndarray):
    """An attacker who tries to swap a sig but uses a known kid loses on signature check."""
    legit_signer = Signer.generate(key_id="test-key-1")
    other_signer = Signer.generate(key_id="test-key-1")  # same kid, different key
    pin = legit_signer.pin(source="x", model="m", vector=vector)
    # Attacker re-signs the modified body but the verifier registry has
    # only the legit public key for this kid, so signature fails.
    forged_sig = other_signer._private_key.sign(pin.header.canonicalize())
    forged = Pin(header=pin.header, sig=forged_sig)
    verifier_with_legit = Verifier({"test-key-1": legit_signer.public_key()})
    result = verifier_with_legit.verify(forged)
    assert not result.ok
    assert result.error is VerifyError.SIGNATURE_INVALID


def test_shape_mismatch_is_caught(signer: Signer, verifier: Verifier, vector: np.ndarray):
    pin = signer.pin(source="x", model="m", vector=vector)
    truncated = vector[:64]
    result = verifier.verify(pin, vector=truncated)
    assert not result.ok
    assert result.error is VerifyError.SHAPE_MISMATCH


def test_model_mismatch_is_caught(signer: Signer, verifier: Verifier, vector: np.ndarray):
    pin = signer.pin(source="x", model="model-A", vector=vector)
    result = verifier.verify(pin, expected_model="model-B")
    assert not result.ok
    assert result.error is VerifyError.MODEL_MISMATCH


def test_key_rotation_works(vector: np.ndarray):
    """Verifier accepts pins from any registered kid."""
    old = Signer.generate(key_id="2026-04")
    new = Signer.generate(key_id="2026-05")
    verifier = Verifier({"2026-04": old.public_key(), "2026-05": new.public_key()})
    assert verifier.verify(old.pin(source="x", model="m", vector=vector))
    assert verifier.verify(new.pin(source="x", model="m", vector=vector))


def test_key_serialization_round_trip(vector: np.ndarray):
    signer = Signer.generate(key_id="k")
    priv_bytes = signer.private_key_bytes()
    pub_bytes = signer.public_key_bytes()
    assert len(priv_bytes) == 32
    assert len(pub_bytes) == 32

    restored_signer = Signer.from_private_bytes(priv_bytes, key_id="k")
    pin = restored_signer.pin(source="x", model="m", vector=vector)

    verifier = Verifier({"k": pub_bytes})
    assert verifier.verify(pin, source="x", vector=vector)


def test_pin_json_round_trip_with_verification(
    signer: Signer, verifier: Verifier, vector: np.ndarray
):
    """A Pin serialized to JSON, stored, and reloaded must still verify."""
    pin = signer.pin(source="hello", model="m", vector=vector)
    json_str = pin.to_json()
    restored = Pin.from_json(json_str)
    assert verifier.verify(restored, source="hello", vector=vector)


def test_verify_rejects_wrong_length_sig(signer: Signer, verifier: Verifier, vector: np.ndarray):
    """A Pin assembled by hand with a too-short sig must fail signature_invalid.

    We bypass Pin.from_dict (which would catch this earlier) by
    constructing the dataclass directly, mirroring what would happen
    if a caller pulled the dataclass straight out of a partially-validated
    pipeline.
    """
    pin = signer.pin(source="x", model="m", vector=vector)
    bad = Pin(header=pin.header, sig=b"\x00" * 32)
    result = verifier.verify(bad)
    assert not result.ok
    assert result.error is VerifyError.SIGNATURE_INVALID
    assert "64 bytes" in result.detail


def test_verify_rejects_non_bytes_sig(signer: Signer, verifier: Verifier, vector: np.ndarray):
    pin = signer.pin(source="x", model="m", vector=vector)
    bad = Pin(header=pin.header, sig="not bytes")  # type: ignore[arg-type]
    result = verifier.verify(bad)
    assert not result.ok
    assert result.error is VerifyError.SIGNATURE_INVALID
