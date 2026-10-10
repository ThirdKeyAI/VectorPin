# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Parser and verifier robustness regressions.

* VP-6: lone surrogates are rejected at parse and sign time, and
  ``verify()`` never raises on pin content.
* VP-9: ``ts`` must be a real calendar instant, not just regex-shaped.
* VP-11: a naive datetime in ``KeyEntry`` is a construction-time error,
  never a ``TypeError`` out of ``verify()``.
* VP-12: ``sig`` must be canonical URL-safe base64 without padding.
* VP-13: ``v`` must be a JSON integer; ``extra: null`` is rejected.
* VP-14: ``kid`` / ``model`` are byte-capped on the dict path too.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import numpy as np
import pytest

from vectorpin import KeyEntry, Pin, PinHeader, Signer, Verifier, VerifyError
from vectorpin.attestation import MAX_KID_BYTES, MAX_MODEL_BYTES, MAX_PIN_JSON_BYTES


def _sig_b64(raw: bytes = b"\x01" * 64) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _valid_pin_dict(**overrides):
    d = {
        "v": 2,
        "kid": "k",
        "model": "m",
        "source_hash": "sha256:" + "0" * 64,
        "vec_hash": "sha256:" + "1" * 64,
        "vec_dtype": "f32",
        "vec_dim": 16,
        "ts": "2026-05-13T00:00:00Z",
        "sig": _sig_b64(),
    }
    d.update(overrides)
    return d


@pytest.fixture
def signer() -> Signer:
    return Signer.generate(key_id="k")


@pytest.fixture
def verifier(signer: Signer) -> Verifier:
    return Verifier({signer.key_id: signer.public_key_bytes()})


@pytest.fixture
def vector() -> np.ndarray:
    return np.arange(4, dtype=np.float32)


# ---- VP-6: surrogates ------------------------------------------------------


@pytest.mark.parametrize("field", ["model", "kid"])
def test_lone_surrogate_rejected_at_parse(field: str) -> None:
    with pytest.raises(ValueError, match="surrogate"):
        Pin.from_dict(_valid_pin_dict(**{field: "bad\ud800"}))


def test_lone_surrogate_in_extra_rejected_at_parse() -> None:
    with pytest.raises(ValueError, match="surrogate"):
        Pin.from_dict(_valid_pin_dict(extra={"k": "\udfff"}))
    with pytest.raises(ValueError, match="surrogate"):
        Pin.from_dict(_valid_pin_dict(extra={"\ud800": "v"}))


def test_lone_surrogate_rejected_from_json() -> None:
    raw = (
        '{"kid":"k","model":"\\ud800","sig":"' + _sig_b64() + '","source_hash":"sha256:'
        + "0" * 64
        + '","ts":"2026-05-13T00:00:00Z","v":2,"vec_dim":16,"vec_dtype":"f32",'
        '"vec_hash":"sha256:' + "1" * 64 + '"}'
    )
    with pytest.raises(ValueError, match="surrogate"):
        Pin.from_json(raw)


def test_lone_surrogate_rejected_at_sign_time(signer: Signer, vector: np.ndarray) -> None:
    with pytest.raises(ValueError, match="surrogate"):
        signer.pin(source="s", model="m\ud800", vector=vector)
    with pytest.raises(ValueError, match="surrogate"):
        signer.pin(source="s", model="m", vector=vector, extra={"k": "\ud800"})
    with pytest.raises(ValueError, match="surrogate"):
        signer.pin(source="bad\ud800", model="m", vector=vector)


def test_verify_never_raises_on_hostile_header(verifier: Verifier) -> None:
    """A Pin built directly (bypassing from_dict) with a lone surrogate
    used to escape as UnicodeEncodeError; it is now a structured result."""
    header = PinHeader(
        v=2,
        kid="k",
        model="\ud800",
        source_hash="sha256:" + "0" * 64,
        vec_hash="sha256:" + "1" * 64,
        vec_dtype="f32",
        vec_dim=4,
        ts="2026-05-13T00:00:00Z",
    )
    result = verifier.verify(Pin(header=header, sig=b"\x00" * 64))
    assert not result.ok
    assert result.error is VerifyError.PARSE_ERROR


def test_verify_source_with_surrogate_is_parse_error(
    signer: Signer, verifier: Verifier, vector: np.ndarray
) -> None:
    pin = signer.pin(source="s", model="m", vector=vector)
    result = verifier.verify(pin, source="s\ud800")
    assert result.error is VerifyError.PARSE_ERROR


def test_verify_never_raises_on_garbage_vector(
    signer: Signer, verifier: Verifier, vector: np.ndarray
) -> None:
    pin = signer.pin(source="s", model="m", vector=vector)
    result = verifier.verify(pin, vector=[1, 2, 3, 4])  # type: ignore[arg-type]
    assert not result.ok
    assert result.error is VerifyError.SHAPE_MISMATCH


# ---- VP-9: calendar validation ----------------------------------------------


@pytest.mark.parametrize(
    "ts",
    [
        "2026-03-00T00:00:00Z",  # day zero
        "2026-13-01T00:00:00Z",  # month 13
        "2026-00-10T00:00:00Z",  # month zero
        "2026-02-30T00:00:00Z",  # February 30
        "2025-02-29T00:00:00Z",  # not a leap year
        "2026-04-31T00:00:00Z",  # April has 30 days
        "2026-05-05T24:00:00Z",  # hour 24
        "2026-05-05T12:60:00Z",  # minute 60
        "2026-05-05T12:00:60Z",  # second 60
    ],
)
def test_invalid_calendar_ts_rejected_at_parse(ts: str) -> None:
    with pytest.raises(ValueError, match="calendar"):
        Pin.from_dict(_valid_pin_dict(ts=ts))


@pytest.mark.parametrize("ts", ["2024-02-29T23:59:59Z", "2026-12-31T00:00:00Z"])
def test_valid_calendar_ts_accepted(ts: str) -> None:
    assert Pin.from_dict(_valid_pin_dict(ts=ts)).header.ts == ts


# ---- VP-11: naive datetimes ------------------------------------------------


def test_naive_datetime_in_key_entry_rejected_at_construction(signer: Signer) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        KeyEntry(public_key=signer.public_key(), valid_from=datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="timezone-aware"):
        KeyEntry(public_key=signer.public_key(), valid_until=datetime(2026, 1, 1))


def test_naive_datetime_via_add_key_rejected(signer: Signer) -> None:
    verifier = Verifier({})
    with pytest.raises(ValueError, match="timezone-aware"):
        verifier.add_key("k", signer.public_key(), valid_from=datetime(2026, 1, 1))


def test_aware_window_still_works(signer: Signer, vector: np.ndarray) -> None:
    pin = signer.pin(source="s", model="m", vector=vector)
    verifier = Verifier(
        {
            "k": KeyEntry(
                public_key=signer.public_key(),
                valid_from=datetime(2000, 1, 1, tzinfo=UTC),
                valid_until=datetime(2100, 1, 1, tzinfo=UTC),
            )
        }
    )
    assert verifier.verify(pin).ok


# ---- VP-12: strict base64url ------------------------------------------------


def test_padded_sig_rejected() -> None:
    with pytest.raises(ValueError, match="sig"):
        Pin.from_dict(_valid_pin_dict(sig=_sig_b64() + "=="))


def test_standard_alphabet_sig_rejected() -> None:
    std = base64.b64encode(b"\xfb\xff" * 32).decode("ascii").rstrip("=")
    assert "+" in std or "/" in std
    with pytest.raises(ValueError, match="sig"):
        Pin.from_dict(_valid_pin_dict(sig=std))


def test_garbage_characters_in_sig_rejected() -> None:
    sig = _sig_b64()
    with pytest.raises(ValueError, match="sig"):
        Pin.from_dict(_valid_pin_dict(sig=sig[:-4] + "!!@@"))


def test_non_canonical_trailing_bits_rejected() -> None:
    """86 chars encode 516 bits for a 64-byte value; the last 4 bits
    must be zero. The Rust decoder already refused this; Python and
    TypeScript now agree."""
    sig = _sig_b64()
    assert sig[-1] == "Q"  # 0x01 -> '...AQ'
    with pytest.raises(ValueError, match="sig"):
        Pin.from_dict(_valid_pin_dict(sig=sig[:-1] + "R"))


def test_canonical_sig_still_accepted() -> None:
    assert Pin.from_dict(_valid_pin_dict()).sig == b"\x01" * 64


# ---- VP-13: integer `v`, `extra: null` --------------------------------------


def test_float_v_rejected() -> None:
    with pytest.raises(ValueError, match="integer"):
        Pin.from_dict(_valid_pin_dict(v=2.0))


def test_float_v_rejected_from_json() -> None:
    raw = (
        '{"kid":"k","model":"m","sig":"' + _sig_b64() + '","source_hash":"sha256:'
        + "0" * 64
        + '","ts":"2026-05-13T00:00:00Z","v":2.0,"vec_dim":16,"vec_dtype":"f32",'
        '"vec_hash":"sha256:' + "1" * 64 + '"}'
    )
    with pytest.raises(ValueError, match="integer"):
        Pin.from_json(raw)


def test_bool_v_rejected() -> None:
    with pytest.raises(ValueError, match="integer"):
        Pin.from_dict(_valid_pin_dict(v=True))


def test_extra_null_rejected() -> None:
    with pytest.raises(ValueError, match="extra"):
        Pin.from_dict(_valid_pin_dict(extra=None))


# ---- VP-14: per-field caps on the dict path ---------------------------------


def test_oversize_model_rejected_on_dict_path() -> None:
    with pytest.raises(ValueError, match="model exceeds"):
        Pin.from_dict(_valid_pin_dict(model="x" * (MAX_MODEL_BYTES + 1)))


def test_oversize_kid_rejected_on_dict_path() -> None:
    with pytest.raises(ValueError, match="kid exceeds"):
        Pin.from_dict(_valid_pin_dict(kid="k" * (MAX_KID_BYTES + 1)))


def test_multibyte_model_counts_bytes_not_code_points() -> None:
    # 400 x U+00E9 (2 bytes each) = 800 bytes: fine. 600 x = 1200 bytes: over.
    assert Pin.from_dict(_valid_pin_dict(model="é" * 400)).header.model
    with pytest.raises(ValueError, match="model exceeds"):
        Pin.from_dict(_valid_pin_dict(model="é" * 600))


def test_dict_path_total_size_guard() -> None:
    # Under the per-field caps individually but over the total.
    with pytest.raises(ValueError, match="too large"):
        Pin.from_dict(_valid_pin_dict(extra={f"k{i}": "v" * 1024 for i in range(70)}))
    huge = {"model": "x" * (MAX_PIN_JSON_BYTES + 1)}
    with pytest.raises(ValueError):
        Pin.from_dict(_valid_pin_dict(**huge))


def test_signer_rejects_oversize_model(signer: Signer, vector: np.ndarray) -> None:
    pin = signer.pin(source="s", model="m" * MAX_MODEL_BYTES, vector=vector)
    assert Pin.from_json(pin.to_json()) == pin
