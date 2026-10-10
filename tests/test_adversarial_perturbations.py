# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""VectorSmuggle-style perturbations must all be detected.

Each case applies a steganographic modification class from the
VectorSmuggle study (noise injection at two magnitudes, orthogonal
rotation, scaling, offset, single-LSB flips in f32, low-bit rewriting
in f64) to a pinned vector and asserts that verification rejects the
result. The f64/f32 case is the channel from VP-1: before the fix it
verified as OK; it is now rejected because the supplied array is wider
than the pinned dtype.
"""

from __future__ import annotations

import numpy as np
import pytest

from vectorpin import Signer, Verifier, VerifyError

DIM = 256


@pytest.fixture(scope="module")
def signer() -> Signer:
    return Signer.generate(key_id="k")


@pytest.fixture(scope="module")
def verifier(signer: Signer) -> Verifier:
    return Verifier({"k": signer.public_key_bytes()})


@pytest.fixture(scope="module")
def base32() -> np.ndarray:
    return np.random.default_rng(0).normal(size=DIM).astype(np.float32)


@pytest.fixture(scope="module")
def base64() -> np.ndarray:
    return np.random.default_rng(0).normal(size=DIM).astype(np.float64)


def _rotation(seed: int = 1) -> np.ndarray:
    q, _ = np.linalg.qr(np.random.default_rng(seed).normal(size=(DIM, DIM)))
    return q


PERTURBATIONS = {
    "noise_1e-3": lambda v: v + np.random.default_rng(3).normal(scale=1e-3, size=v.shape),
    "noise_1e-5": lambda v: v + np.random.default_rng(4).normal(scale=1e-5, size=v.shape),
    "rotation": lambda v: _rotation() @ v,
    "scaling": lambda v: v * 1.0001,
    "offset": lambda v: v + 1e-4,
    "lsb_flip_one_element": lambda v: _flip_lsb(v, (0,)),
    "lsb_flip_all_elements": lambda v: _flip_lsb(v, range(v.shape[0])),
}


def _flip_lsb(v: np.ndarray, idx) -> np.ndarray:
    out = v.copy()
    int_view = out.view(np.uint32 if out.dtype == np.float32 else np.uint64)
    for i in idx:
        int_view[i] ^= 1
    return out


@pytest.mark.parametrize("name", sorted(PERTURBATIONS))
def test_perturbation_detected_in_f32(
    signer: Signer, verifier: Verifier, base32: np.ndarray, name: str
) -> None:
    pin = signer.pin(source="s", model="m", vector=base32)
    perturbed = np.asarray(PERTURBATIONS[name](base32), dtype=np.float32)
    assert not np.array_equal(perturbed, base32)
    result = verifier.verify(pin, vector=perturbed)
    assert result.error is VerifyError.VECTOR_TAMPERED, name


@pytest.mark.parametrize("name", sorted(PERTURBATIONS))
def test_perturbation_detected_in_f64(
    signer: Signer, verifier: Verifier, base64: np.ndarray, name: str
) -> None:
    pin = signer.pin(source="s", model="m", vector=base64)
    perturbed = np.asarray(PERTURBATIONS[name](base64), dtype=np.float64)
    assert not np.array_equal(perturbed, base64)
    result = verifier.verify(pin, vector=perturbed)
    assert result.error is VerifyError.VECTOR_TAMPERED, name


def test_f64_low_bits_under_f32_pin_are_rejected(
    signer: Signer, verifier: Verifier, base64: np.ndarray
) -> None:
    """The VP-1 channel: ~28 bits/element hidden below f32 precision.
    Before the fix this returned OK; the verifier now refuses the wider
    array outright."""
    pin = signer.pin(source="s", model="m", vector=base64, vec_dtype="f32")
    bits = base64.view(np.uint64).copy()
    payload = np.random.default_rng(9).integers(1, 1 << 28, size=DIM, dtype=np.uint64)
    bits = (bits & ~np.uint64((1 << 28) - 1)) | payload
    smuggled = bits.view(np.float64)
    assert np.array_equal(smuggled.astype(np.float32), base64.astype(np.float32))
    assert np.abs(smuggled - base64).max() < 1e-6
    result = verifier.verify(pin, vector=smuggled)
    assert not result.ok
    assert result.error is VerifyError.SHAPE_MISMATCH


def test_honest_vectors_still_verify(
    signer: Signer, verifier: Verifier, base32: np.ndarray, base64: np.ndarray
) -> None:
    assert verifier.verify(signer.pin(source="s", model="m", vector=base32), vector=base32).ok
    assert verifier.verify(signer.pin(source="s", model="m", vector=base64), vector=base64).ok
