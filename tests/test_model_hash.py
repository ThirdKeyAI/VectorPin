# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""VP-10: ``model_hash`` is signed but was never verifiable.

``expected_model_hash`` lets a verifier require a specific weights
hash, and ``hash_files`` computes it per the spec §4.1 convention.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pytest

from vectorpin import Signer, Verifier, VerifyError, hash_files


@pytest.fixture
def signer() -> Signer:
    return Signer.generate(key_id="k")


@pytest.fixture
def verifier(signer: Signer) -> Verifier:
    return Verifier({signer.key_id: signer.public_key_bytes()})


@pytest.fixture
def vector() -> np.ndarray:
    return np.arange(4, dtype=np.float32)


GOOD = "sha256:" + "a" * 64
BAD = "sha256:" + "b" * 64


def test_expected_model_hash_match_passes(
    signer: Signer, verifier: Verifier, vector: np.ndarray
) -> None:
    pin = signer.pin(source="s", model="m", vector=vector, model_hash=GOOD)
    assert verifier.verify(pin, expected_model_hash=GOOD).ok


def test_expected_model_hash_mismatch_fails(
    signer: Signer, verifier: Verifier, vector: np.ndarray
) -> None:
    pin = signer.pin(source="s", model="m", vector=vector, model_hash=GOOD)
    result = verifier.verify(pin, expected_model_hash=BAD)
    assert result.error is VerifyError.MODEL_MISMATCH


def test_pin_without_model_hash_fails_when_one_is_expected(
    signer: Signer, verifier: Verifier, vector: np.ndarray
) -> None:
    pin = signer.pin(source="s", model="m", vector=vector)
    result = verifier.verify(pin, expected_model_hash=GOOD)
    assert result.error is VerifyError.MODEL_MISMATCH


def test_hash_files_sorts_by_basename_and_streams(tmp_path: Path) -> None:
    (tmp_path / "model-00002-of-00002.safetensors").write_bytes(b"second")
    (tmp_path / "model-00001-of-00002.safetensors").write_bytes(b"first")
    expected = "sha256:" + hashlib.sha256(b"firstsecond").hexdigest()
    paths = [
        tmp_path / "model-00002-of-00002.safetensors",
        tmp_path / "model-00001-of-00002.safetensors",
    ]
    assert hash_files(paths) == expected
    assert hash_files(reversed(paths)) == expected
