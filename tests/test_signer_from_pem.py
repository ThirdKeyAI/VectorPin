# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the explicit unencrypted opt-in on Signer.from_pem.

Loading an unencrypted PEM key by default is a footgun (key material
sitting on disk in cleartext). We require callers to either supply a
password or pass `allow_unencrypted=True` so the choice is visible at
the call site.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vectorpin import Signer


def _make_unencrypted_pem() -> bytes:
    """A freshly-generated ed25519 private key in PEM PKCS#8, no password."""
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _make_encrypted_pem(password: bytes) -> bytes:
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )


def test_from_pem_refuses_unencrypted_by_default():
    pem = _make_unencrypted_pem()
    with pytest.raises(ValueError, match="allow_unencrypted"):
        Signer.from_pem(pem, key_id="k")


def test_from_pem_allows_unencrypted_with_explicit_opt_in():
    pem = _make_unencrypted_pem()
    signer = Signer.from_pem(pem, key_id="k", allow_unencrypted=True)
    assert signer.key_id == "k"
    assert len(signer.private_key_bytes()) == 32


def test_from_pem_with_password_does_not_require_opt_in():
    password = b"correct horse battery staple"
    pem = _make_encrypted_pem(password)
    signer = Signer.from_pem(pem, key_id="k", password=password)
    assert signer.key_id == "k"


def test_from_pem_wrong_password_raises():
    pem = _make_encrypted_pem(b"right")
    # cryptography raises ValueError on a wrong password — that's the
    # contract we care about: bad password is not silently accepted.
    with pytest.raises(ValueError):
        Signer.from_pem(pem, key_id="k", password=b"wrong")
