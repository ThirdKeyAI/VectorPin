# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Replay-protection identifiers (§5 step 8, §8 reserved keys).

Callers can pin `vectorpin.record_id` / `vectorpin.collection_id` /
`vectorpin.tenant_id` into the signed `extra` map, then ask the
verifier to enforce that the pin matches the expected identifiers at
verify time. Because every `extra` entry is signed, a mismatch is
proof of replay (copying a pin from one record/collection/tenant to
another) rather than a regular bit flip.
"""

from __future__ import annotations

import numpy as np
import pytest

from vectorpin import Signer, Verifier, VerifyError


@pytest.fixture
def signer() -> Signer:
    return Signer.generate(key_id="prod")


@pytest.fixture
def verifier(signer: Signer) -> Verifier:
    return Verifier({signer.key_id: signer.public_key()})


@pytest.fixture
def vector() -> np.ndarray:
    return np.arange(8, dtype=np.float32)


# ---- record_id ----


def test_record_id_match_passes(signer: Signer, verifier: Verifier, vector: np.ndarray):
    pin = signer.pin(
        source="x",
        model="m",
        vector=vector,
        extra={"vectorpin.record_id": "rec-42"},
    )
    result = verifier.verify(pin, expected_record_id="rec-42")
    assert result.ok


def test_record_id_mismatch_returns_record_mismatch(
    signer: Signer, verifier: Verifier, vector: np.ndarray
):
    pin = signer.pin(
        source="x",
        model="m",
        vector=vector,
        extra={"vectorpin.record_id": "rec-42"},
    )
    result = verifier.verify(pin, expected_record_id="rec-99")
    assert not result.ok
    assert result.error is VerifyError.RECORD_MISMATCH


def test_record_id_missing_returns_record_mismatch(
    signer: Signer, verifier: Verifier, vector: np.ndarray
):
    """If the caller expects a record_id but the pin has none, fail."""
    pin = signer.pin(source="x", model="m", vector=vector)
    result = verifier.verify(pin, expected_record_id="rec-42")
    assert not result.ok
    assert result.error is VerifyError.RECORD_MISMATCH


# ---- collection_id ----


def test_collection_id_match_passes(signer: Signer, verifier: Verifier, vector: np.ndarray):
    pin = signer.pin(
        source="x",
        model="m",
        vector=vector,
        extra={"vectorpin.collection_id": "col-A"},
    )
    result = verifier.verify(pin, expected_collection_id="col-A")
    assert result.ok


def test_collection_id_mismatch_returns_collection_mismatch(
    signer: Signer, verifier: Verifier, vector: np.ndarray
):
    pin = signer.pin(
        source="x",
        model="m",
        vector=vector,
        extra={"vectorpin.collection_id": "col-A"},
    )
    result = verifier.verify(pin, expected_collection_id="col-B")
    assert not result.ok
    assert result.error is VerifyError.COLLECTION_MISMATCH


# ---- tenant_id ----


def test_tenant_id_match_passes(signer: Signer, verifier: Verifier, vector: np.ndarray):
    pin = signer.pin(
        source="x",
        model="m",
        vector=vector,
        extra={"vectorpin.tenant_id": "tenant-1"},
    )
    result = verifier.verify(pin, expected_tenant_id="tenant-1")
    assert result.ok


def test_tenant_id_mismatch_returns_tenant_mismatch(
    signer: Signer, verifier: Verifier, vector: np.ndarray
):
    pin = signer.pin(
        source="x",
        model="m",
        vector=vector,
        extra={"vectorpin.tenant_id": "tenant-1"},
    )
    result = verifier.verify(pin, expected_tenant_id="tenant-2")
    assert not result.ok
    assert result.error is VerifyError.TENANT_MISMATCH


# ---- combined ----


def test_all_three_identifiers_pass_when_matched(
    signer: Signer, verifier: Verifier, vector: np.ndarray
):
    pin = signer.pin(
        source="x",
        model="m",
        vector=vector,
        extra={
            "vectorpin.record_id": "rec-1",
            "vectorpin.collection_id": "col-1",
            "vectorpin.tenant_id": "ten-1",
        },
    )
    result = verifier.verify(
        pin,
        expected_record_id="rec-1",
        expected_collection_id="col-1",
        expected_tenant_id="ten-1",
    )
    assert result.ok


def test_no_expected_identifiers_skips_replay_check(
    signer: Signer, verifier: Verifier, vector: np.ndarray
):
    """When the caller supplies none of the replay identifiers, the
    pin's `extra` is signed but not enforced — backward-compatible
    behaviour for callers that don't opt in."""
    pin = signer.pin(
        source="x",
        model="m",
        vector=vector,
        extra={"vectorpin.record_id": "rec-1"},
    )
    result = verifier.verify(pin)
    assert result.ok


def test_replay_check_runs_after_signature_check(
    signer: Signer, verifier: Verifier, vector: np.ndarray
):
    """A tampered signature must surface as SIGNATURE_INVALID, not
    RECORD_MISMATCH, even if a replay identifier mismatches.

    Order of errors matters: callers route on the first failure mode
    and we want signature failures to take precedence over policy
    mismatches.
    """
    pin = signer.pin(
        source="x",
        model="m",
        vector=vector,
        extra={"vectorpin.record_id": "rec-1"},
    )
    # Flip a bit in the signature.
    bad_sig = bytearray(pin.sig)
    bad_sig[0] ^= 0x01
    from vectorpin import Pin

    forged = Pin(header=pin.header, sig=bytes(bad_sig))
    result = verifier.verify(forged, expected_record_id="rec-99")
    assert result.error is VerifyError.SIGNATURE_INVALID
