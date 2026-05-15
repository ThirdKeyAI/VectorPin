# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Attestation format and round-trip tests (v2 protocol)."""

import base64
import json

import pytest

from vectorpin.attestation import DOMAIN_TAG, PROTOCOL_VERSION, Pin, PinHeader


def _header(**overrides) -> PinHeader:
    base = {
        "v": PROTOCOL_VERSION,
        "kid": "prod-2026-05",
        "model": "text-embedding-3-large",
        "source_hash": "sha256:" + "0" * 64,
        "vec_hash": "sha256:" + "1" * 64,
        "vec_dtype": "f32",
        "vec_dim": 3072,
        "ts": "2026-05-05T12:00:00Z",
    }
    base.update(overrides)
    return PinHeader(**base)


def test_canonicalize_starts_with_domain_tag():
    """The whole point of v2: signed bytes begin with the domain tag."""
    raw = _header().canonicalize()
    assert raw.startswith(DOMAIN_TAG)
    assert raw.startswith(b"vectorpin/v2\x00")


def test_canonicalize_is_deterministic():
    h = _header()
    assert h.canonicalize() == h.canonicalize()


def test_canonicalize_is_key_order_independent():
    a = _header(extra={"a": "1", "b": "2"})
    b = _header(extra={"b": "2", "a": "1"})
    assert a.canonicalize() == b.canonicalize()


def test_canonicalize_omits_optional_fields_when_unset():
    raw = _header().canonicalize().decode()
    assert "model_hash" not in raw
    assert "extra" not in raw


def test_canonicalize_includes_optional_fields_when_set():
    h = _header(model_hash="sha256:" + "f" * 64, extra={"region": "us-west"})
    raw = h.canonicalize().decode()
    assert "model_hash" in raw
    assert "extra" in raw
    assert "us-west" in raw


def test_canonicalize_includes_v_and_kid():
    """v2: both `v` and `kid` are part of the signed canonical bytes."""
    raw = _header(kid="prod-2026-05").canonicalize().decode()
    # The domain tag is binary so split on it.
    body = raw.split("\x00", 1)[1]
    parsed = json.loads(body)
    assert parsed["v"] == 2
    assert parsed["kid"] == "prod-2026-05"


def test_pin_to_json_round_trip():
    pin = Pin(header=_header(), sig=b"\x01" * 64)
    restored = Pin.from_json(pin.to_json())
    assert restored == pin


def test_pin_kid_property():
    pin = Pin(header=_header(kid="my-key"), sig=b"\x01" * 64)
    assert pin.kid == "my-key"


def test_pin_from_dict_rejects_unsupported_version():
    bad = {
        "v": 99,
        "kid": "k",
        "model": "x",
        "source_hash": "sha256:" + "0" * 64,
        "vec_hash": "sha256:" + "1" * 64,
        "vec_dtype": "f32",
        "vec_dim": 1,
        "ts": "2026-05-05T12:00:00Z",
        "sig": base64.urlsafe_b64encode(b"\x01" * 64).rstrip(b"=").decode("ascii"),
    }
    with pytest.raises(ValueError, match="version"):
        Pin.from_dict(bad)


def test_pin_json_is_compact():
    """Pin JSON must fit in vector DB metadata fields without fuss."""
    pin = Pin(header=_header(), sig=b"\x01" * 64)
    j = pin.to_json()
    parsed = json.loads(j)
    assert "model" in parsed
    # No whitespace, sorted keys.
    assert ": " not in j
    assert ", " not in j


# ---- strict validation in from_dict / from_json ----


def _valid_pin_dict(**overrides):
    """A baseline dict that passes from_dict, plus an override hook."""
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


def test_from_json_rejects_oversized_payload():
    # MAX_PIN_JSON_BYTES is 64 KiB; anything bigger must be refused
    # before json.loads runs.
    huge = '{"v":2,"junk":"' + ("a" * 70_000) + '"}'
    with pytest.raises(ValueError, match="too large"):
        Pin.from_json(huge)


def test_from_dict_rejects_wrong_version():
    with pytest.raises(ValueError, match="version"):
        Pin.from_dict(_valid_pin_dict(v=1))


def test_from_dict_rejects_bad_vec_dtype():
    with pytest.raises(ValueError, match="vec_dtype"):
        Pin.from_dict(_valid_pin_dict(vec_dtype="f16"))


def test_from_dict_rejects_negative_vec_dim():
    with pytest.raises(ValueError, match="vec_dim"):
        Pin.from_dict(_valid_pin_dict(vec_dim=-1))


def test_from_dict_rejects_zero_vec_dim():
    with pytest.raises(ValueError, match="vec_dim"):
        Pin.from_dict(_valid_pin_dict(vec_dim=0))


def test_from_dict_rejects_huge_vec_dim():
    with pytest.raises(ValueError, match="vec_dim"):
        Pin.from_dict(_valid_pin_dict(vec_dim=10_000_000))


def test_from_dict_rejects_non_int_vec_dim():
    with pytest.raises(ValueError, match="vec_dim"):
        Pin.from_dict(_valid_pin_dict(vec_dim="3072"))


def test_from_dict_rejects_bool_vec_dim():
    # bool is technically a subclass of int — we explicitly reject it.
    with pytest.raises(ValueError, match="vec_dim"):
        Pin.from_dict(_valid_pin_dict(vec_dim=True))


def test_from_dict_rejects_malformed_source_hash():
    with pytest.raises(ValueError, match="source_hash"):
        Pin.from_dict(_valid_pin_dict(source_hash="md5:beef"))


def test_from_dict_rejects_malformed_vec_hash():
    with pytest.raises(ValueError, match="vec_hash"):
        Pin.from_dict(_valid_pin_dict(vec_hash="sha256:short"))


def test_from_dict_rejects_uppercase_hash_hex():
    # Lowercase hex only — matches what hash.py produces.
    with pytest.raises(ValueError, match="source_hash"):
        Pin.from_dict(_valid_pin_dict(source_hash="sha256:" + "A" * 64))


def test_from_dict_rejects_wrong_sig_length():
    short_sig = base64.urlsafe_b64encode(b"\x01" * 32).rstrip(b"=").decode("ascii")
    with pytest.raises(ValueError, match="sig"):
        Pin.from_dict(_valid_pin_dict(sig=short_sig))


def test_from_dict_rejects_non_base64_sig():
    with pytest.raises(ValueError, match="sig"):
        Pin.from_dict(_valid_pin_dict(sig="!!!not_base64!!!"))


def test_from_dict_rejects_empty_model():
    with pytest.raises(ValueError, match="model"):
        Pin.from_dict(_valid_pin_dict(model=""))


def test_from_dict_rejects_empty_kid():
    with pytest.raises(ValueError, match="kid"):
        Pin.from_dict(_valid_pin_dict(kid=""))


def test_from_dict_rejects_non_string_extra_value():
    with pytest.raises(ValueError, match="extra values"):
        Pin.from_dict(_valid_pin_dict(extra={"region": 5}))


def test_from_dict_rejects_non_string_extra_key():
    with pytest.raises(ValueError, match="extra keys"):
        Pin.from_dict(_valid_pin_dict(extra={5: "x"}))


def test_from_dict_accepts_valid_pin():
    # Sanity check that the baseline isn't accidentally rejected.
    pin = Pin.from_dict(_valid_pin_dict())
    assert pin.header.vec_dim == 16
    assert pin.kid == "k"
