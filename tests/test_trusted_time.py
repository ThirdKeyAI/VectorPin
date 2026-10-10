# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""VP-5: the revocation window is keyed on a signer-chosen ``ts``.

An attacker holding a compromised key can backdate ``ts`` to any
instant before ``valid_until`` and the forged pin verifies. The
``trusted_time`` hook lets a caller supply an instant from a clock the
key holder cannot write (the store's ingestion timestamp); the window
is then evaluated against that instant, and a pin whose ``ts`` is later
than it is rejected outright.
"""

from __future__ import annotations

from datetime import UTC, datetime

import numpy as np
import pytest

from vectorpin import KeyEntry, Signer, Verifier, VerifyError

COMPROMISE = datetime(2026, 6, 1, tzinfo=UTC)


@pytest.fixture
def signer() -> Signer:
    return Signer.generate(key_id="k")


@pytest.fixture
def verifier(signer: Signer) -> Verifier:
    return Verifier({"k": KeyEntry(public_key=signer.public_key(), valid_until=COMPROMISE)})


@pytest.fixture
def vector() -> np.ndarray:
    return np.arange(4, dtype=np.float32)


def test_backdated_forgery_passes_without_trusted_time(
    signer: Signer, verifier: Verifier, vector: np.ndarray
) -> None:
    """Documents the limitation: `ts` alone cannot stop a backdated forgery."""
    forged = signer.pin(
        source="s", model="m", vector=vector, timestamp=datetime(2026, 5, 1, tzinfo=UTC)
    )
    assert verifier.verify(forged).ok


def test_backdated_forgery_fails_with_trusted_ingestion_time(
    signer: Signer, verifier: Verifier, vector: np.ndarray
) -> None:
    forged = signer.pin(
        source="s", model="m", vector=vector, timestamp=datetime(2026, 5, 1, tzinfo=UTC)
    )
    ingested_after_compromise = datetime(2026, 7, 1, tzinfo=UTC)
    result = verifier.verify(forged, trusted_time=ingested_after_compromise)
    assert not result.ok
    assert result.error is VerifyError.KEY_EXPIRED
    assert "valid_until" in result.detail


def test_honest_pin_passes_with_trusted_time(
    signer: Signer, verifier: Verifier, vector: np.ndarray
) -> None:
    pin = signer.pin(
        source="s", model="m", vector=vector, timestamp=datetime(2026, 5, 1, tzinfo=UTC)
    )
    assert verifier.verify(pin, trusted_time=datetime(2026, 5, 1, 0, 0, 30, tzinfo=UTC)).ok


def test_pin_ts_after_trusted_time_rejected(
    signer: Signer, vector: np.ndarray
) -> None:
    """A pin cannot honestly claim to have been signed after it was ingested."""
    verifier = Verifier({"k": signer.public_key()})  # no window at all
    pin = signer.pin(
        source="s", model="m", vector=vector, timestamp=datetime(2026, 5, 2, tzinfo=UTC)
    )
    result = verifier.verify(pin, trusted_time=datetime(2026, 5, 1, tzinfo=UTC))
    assert result.error is VerifyError.KEY_EXPIRED
    assert "postdates" in result.detail


def test_trusted_time_must_be_aware(signer: Signer, verifier: Verifier, vector: np.ndarray) -> None:
    pin = signer.pin(source="s", model="m", vector=vector)
    result = verifier.verify(pin, trusted_time=datetime(2026, 5, 1))
    # Never raises; reported as a structured error.
    assert not result.ok
    assert result.error is VerifyError.PARSE_ERROR
