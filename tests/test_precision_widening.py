# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""VP-1: cast-before-hash must not leave low-order bits unverified.

Before the fix, a verifier cast whatever array it was handed to the
pinned dtype and hashed the result, so every float64 value that rounds
to the same float32 verified identically against an f32 pin: ~28 bits
per element of covert channel in any store that persists float64.
The verifier now refuses a supplied vector wider than the pinned dtype,
adapters hand back the store's native precision, and the signer pins
under the input's native dtype by default.
"""

from __future__ import annotations

import numpy as np
import pytest

from vectorpin import Signer, Verifier, VerifyError, native_dtype
from vectorpin.hash import is_wider_than


@pytest.fixture
def signer() -> Signer:
    return Signer.generate(key_id="k")


@pytest.fixture
def verifier(signer: Signer) -> Verifier:
    return Verifier({signer.key_id: signer.public_key_bytes()})


def _f64_vector(dim: int = 3072, seed: int = 1) -> np.ndarray:
    return np.random.default_rng(seed).normal(size=dim).astype(np.float64)


def _hide_payload_in_low_bits(v64: np.ndarray, seed: int = 2) -> np.ndarray:
    """Rewrite the low 28 mantissa bits of every element with random
    payload while keeping each element's float32 rounding unchanged."""
    rng = np.random.default_rng(seed)
    bits = v64.view(np.uint64).copy()
    payload = rng.integers(1, 1 << 28, size=v64.shape[0], dtype=np.uint64)
    # A double has 52 mantissa bits, a float32 23; the f64->f32 cast
    # looks at bit 28 (the rounding bit) and treats bits 0..27 as the
    # sticky bits. Replacing bits 0..27 with a non-zero payload while
    # leaving bit 28 alone keeps every element in the same f32 bucket.
    mask = np.uint64((1 << 28) - 1)
    bits = (bits & ~mask) | payload
    modified = bits.view(np.float64)
    assert np.array_equal(modified.astype(np.float32), v64.astype(np.float32))
    assert not np.array_equal(modified, v64)
    return modified


def test_f64_low_bit_channel_is_rejected_against_f32_pin(
    signer: Signer, verifier: Verifier
) -> None:
    """The headline regression: an f32 pin over f64 input must not
    accept an f64 vector whose low-order bits were rewritten."""
    v64 = _f64_vector()
    pin = signer.pin(source="s", model="m", vector=v64, vec_dtype="f32")
    assert pin.header.vec_dtype == "f32"
    modified = _hide_payload_in_low_bits(v64)
    assert np.abs(modified - v64).max() < 1e-6

    result = verifier.verify(pin, vector=modified)
    assert not result.ok
    assert result.error is VerifyError.SHAPE_MISMATCH
    assert "wider" in result.detail

    # Even the *unmodified* f64 array is refused for an f32 pin: the
    # verifier cannot tell which bits the store might have changed.
    result = verifier.verify(pin, vector=v64)
    assert not result.ok
    assert result.error is VerifyError.SHAPE_MISMATCH

    # The honest f32 representation (what an f32 store persists) passes.
    assert verifier.verify(pin, vector=v64.astype(np.float32)).ok


def test_f64_pin_catches_low_bit_modification(signer: Signer, verifier: Verifier) -> None:
    """Pinned under the native f64 dtype, the same perturbation is a
    plain VECTOR_TAMPERED."""
    v64 = _f64_vector()
    pin = signer.pin(source="s", model="m", vector=v64)
    assert pin.header.vec_dtype == "f64"
    result = verifier.verify(pin, vector=_hide_payload_in_low_bits(v64))
    assert result.error is VerifyError.VECTOR_TAMPERED
    assert verifier.verify(pin, vector=v64).ok


def test_narrower_than_pinned_is_allowed(signer: Signer, verifier: Verifier) -> None:
    v32 = _f64_vector(dim=8).astype(np.float32)
    pin = signer.pin(source="s", model="m", vector=v32, vec_dtype="f64")
    assert pin.header.vec_dtype == "f64"
    # Widening at verify time is exact, so the f32 array still hashes equal.
    assert verifier.verify(pin, vector=v32).ok
    assert verifier.verify(pin, vector=v32.astype(np.float64)).ok
    # float16 is narrower still.
    v16 = np.array([0.5, 0.25, 1.0], dtype=np.float16)
    pin16 = signer.pin(source="s", model="m", vector=v16)
    assert pin16.header.vec_dtype == "f32"
    assert verifier.verify(pin16, vector=v16).ok


def test_non_float_arrays_are_rejected_at_verify(signer: Signer, verifier: Verifier) -> None:
    v = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    pin = signer.pin(source="s", model="m", vector=v)
    result = verifier.verify(pin, vector=np.array([1, 2, 3], dtype=np.int32))
    assert result.error is VerifyError.SHAPE_MISMATCH


def test_signer_defaults_to_native_dtype(signer: Signer) -> None:
    v64 = np.array([0.1, 0.2], dtype=np.float64)
    v32 = v64.astype(np.float32)
    assert signer.pin(source="s", model="m", vector=v64).header.vec_dtype == "f64"
    assert signer.pin(source="s", model="m", vector=v32).header.vec_dtype == "f32"
    # Explicit override still works and commits to the f32 rounding.
    pin = signer.pin(source="s", model="m", vector=v64, vec_dtype="f32")
    assert pin.header.vec_dtype == "f32"


def test_signer_refuses_to_guess_for_non_float_input(signer: Signer) -> None:
    with pytest.raises(ValueError, match="pass vec_dtype explicitly"):
        signer.pin(source="s", model="m", vector=np.array([1, 2, 3]))
    pin = signer.pin(source="s", model="m", vector=np.array([1, 2, 3]), vec_dtype="f32")
    assert pin.header.vec_dtype == "f32"


def test_signer_rejects_empty_vector(signer: Signer) -> None:
    """VP-16: an empty vector produced a vec_dim=0 pin that no parser accepts."""
    with pytest.raises(ValueError, match="empty"):
        signer.pin(source="s", model="m", vector=np.zeros((0,), dtype=np.float32))


def test_native_dtype_helper() -> None:
    assert native_dtype(np.zeros(2, dtype=np.float16)) == "f32"
    assert native_dtype(np.zeros(2, dtype=np.float32)) == "f32"
    assert native_dtype(np.zeros(2, dtype=np.float64)) == "f64"
    with pytest.raises(ValueError):
        native_dtype(np.zeros(2, dtype=np.int64))
    assert is_wider_than(np.zeros(2, dtype=np.float64), "f32")
    assert not is_wider_than(np.zeros(2, dtype=np.float64), "f64")
    assert not is_wider_than(np.zeros(2, dtype=np.float32), "f32")
    assert is_wider_than(np.zeros(2, dtype=np.int8), "f64")


def test_tampered_detail_hints_at_dtype_mismatch(signer: Signer, verifier: Verifier) -> None:
    """An f64 pin verified with the f32 the store persisted is a hash
    mismatch; the detail tells the operator which dtype to pin under."""
    v64 = _f64_vector(dim=8)
    pin = signer.pin(source="s", model="m", vector=v64)
    result = verifier.verify(pin, vector=v64.astype(np.float32))
    assert result.error is VerifyError.VECTOR_TAMPERED
    assert "vec_dtype='f32'" in result.detail
