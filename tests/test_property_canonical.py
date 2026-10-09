# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Property tests for canonical bytes and pin round-trips (hypothesis)."""

from __future__ import annotations

import json
import struct
import unicodedata

import numpy as np
import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings
from hypothesis import strategies as st

from vectorpin import DOMAIN_TAG, Pin, Signer, Verifier, canonical_vector_bytes, hash_vector

SIGNER = Signer.generate(key_id="prop")
VERIFIER = Verifier({"prop": SIGNER.public_key_bytes()})

finite_f32 = st.floats(width=32, allow_nan=False, allow_infinity=False)
finite_f64 = st.floats(width=64, allow_nan=False, allow_infinity=False)
# f64 values whose f32 cast stays finite (the signer refuses overflow anyway).
f32_range_f64 = st.floats(
    min_value=-3.4028234663852886e38,
    max_value=3.4028234663852886e38,
    allow_nan=False,
    allow_infinity=False,
)


@given(st.lists(finite_f32, min_size=1, max_size=64))
@settings(max_examples=200)
def test_f32_canonical_bytes_are_packed_little_endian(values: list[float]) -> None:
    arr = np.array(values, dtype=np.float32)
    expected = b"".join(struct.pack("<f", float(x)) for x in arr)
    assert canonical_vector_bytes(arr, "f32") == expected
    # Byte-exact round trip: the bytes decode to the same array
    # (bit-for-bit, so -0.0 and subnormals survive).
    back = np.frombuffer(canonical_vector_bytes(arr, "f32"), dtype="<f4")
    assert back.tobytes() == arr.astype("<f4").tobytes()


@given(st.lists(finite_f64, min_size=1, max_size=64))
@settings(max_examples=200)
def test_f64_canonical_bytes_are_packed_little_endian(values: list[float]) -> None:
    arr = np.array(values, dtype=np.float64)
    expected = b"".join(struct.pack("<d", float(x)) for x in arr)
    assert canonical_vector_bytes(arr, "f64") == expected


@given(st.lists(f32_range_f64, min_size=1, max_size=64))
@settings(max_examples=200)
def test_f64_to_f32_cast_is_round_to_nearest_even(values: list[float]) -> None:
    arr = np.array(values, dtype=np.float64)
    expected = b"".join(struct.pack("<f", float(np.float32(x))) for x in arr)
    # struct.pack('<f') of a Python float rounds to nearest even, as
    # does numpy's astype; the Rust `as f32` and JS setFloat32 agree.
    assert canonical_vector_bytes(arr, "f32") == expected


@given(st.lists(finite_f32, min_size=1, max_size=32))
@settings(max_examples=100)
def test_hash_is_stable_under_copy_and_contiguity(values: list[float]) -> None:
    arr = np.array(values, dtype=np.float32)
    strided = np.repeat(arr, 2)[::2]
    assert not strided.flags["C_CONTIGUOUS"] or strided.shape[0] == 1
    assert hash_vector(arr, "f32") == hash_vector(strided, "f32")


safe_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cc", "Cs"),
        blacklist_characters="‪‫‬‭‮⁦⁧⁨⁩",
    ),
    min_size=1,
    max_size=40,
)


@given(
    model=safe_text,
    source=st.text(max_size=100),
    vec=st.lists(finite_f32, min_size=1, max_size=8),
)
@settings(max_examples=100, deadline=None)
def test_pin_round_trips_through_json_and_verifies(
    model: str, source: str, vec: list[float]
) -> None:
    arr = np.array(vec, dtype=np.float32)
    pin = SIGNER.pin(source=source, model=model, vector=arr)
    wire = pin.to_json()
    back = Pin.from_json(wire)
    assert back == pin
    assert VERIFIER.verify(back, source=source, vector=arr).ok
    # Canonical bytes: domain tag + compact sorted JSON of the header.
    canonical = pin.header.canonicalize()
    assert canonical.startswith(DOMAIN_TAG)
    body = json.loads(canonical[len(DOMAIN_TAG) :])
    assert body["model"] == unicodedata.normalize("NFC", model)
    assert list(body) == sorted(body)
