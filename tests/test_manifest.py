# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Collection manifest: Merkle root, signing, parsing, verification."""

from __future__ import annotations

import hashlib
import json

import pytest

from vectorpin import (
    CollectionManifest,
    ManifestError,
    Signer,
    Verifier,
    build_manifest,
    merkle_root,
    verify_manifest,
)
from vectorpin.manifest import MANIFEST_DOMAIN_TAG


@pytest.fixture
def signer() -> Signer:
    return Signer.generate(key_id="manifest-key")


@pytest.fixture
def verifier(signer: Signer) -> Verifier:
    return Verifier({signer.key_id: signer.public_key_bytes()})


H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64


def test_merkle_root_is_order_independent() -> None:
    a = merkle_root([("a", H1), ("b", H2), ("c", H3)])
    b = merkle_root([("c", H3), ("a", H1), ("b", H2)])
    assert a == b
    assert a.startswith("sha256:") and len(a) == 71


def test_merkle_root_changes_on_any_edit() -> None:
    base = merkle_root([("a", H1), ("b", H2)])
    assert merkle_root([("a", H1), ("b", H3)]) != base  # re-pinned
    assert merkle_root([("a", H1), ("b", "")]) != base  # pin stripped
    assert merkle_root([("a", H1)]) != base  # deleted
    assert merkle_root([("a", H1), ("b", H2), ("c", "")]) != base  # inserted unpinned
    assert merkle_root([("a", H1), ("b2", H2)]) != base  # renamed


def test_merkle_root_empty_and_single() -> None:
    assert merkle_root([]) == "sha256:" + hashlib.sha256(b"").hexdigest()
    single = merkle_root([("a", H1)])
    leaf = hashlib.sha256(b"\x00" + b"a" + b"\x00" + H1.encode()).hexdigest()
    assert single == "sha256:" + leaf


def test_merkle_root_rejects_duplicate_ids() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        merkle_root([("a", H1), ("a", H2)])


def test_build_sign_round_trip(signer: Signer, verifier: Verifier) -> None:
    m = build_manifest(signer, "rag-corpus", [("a", H1), ("b", H2)])
    assert m.count == 2 and m.kid == "manifest-key"
    parsed = CollectionManifest.from_json(m.to_json())
    assert parsed == m
    assert verify_manifest(parsed, verifier, [("b", H2), ("a", H1)]).ok


def test_verify_manifest_outcomes(signer: Signer, verifier: Verifier) -> None:
    m = build_manifest(signer, "rag-corpus", [("a", H1), ("b", H2)])
    r = verify_manifest(m, verifier, [("a", H1)])
    assert r.error is ManifestError.COUNT_MISMATCH
    r = verify_manifest(m, verifier, [("a", H1), ("b", H3)])
    assert r.error is ManifestError.ROOT_MISMATCH
    r = verify_manifest(m, verifier, [("a", H1), ("b", H2)], expected_collection_id="other")
    assert r.error is ManifestError.COLLECTION_MISMATCH
    r = verify_manifest(m, Verifier({}), [("a", H1), ("b", H2)])
    assert r.error is ManifestError.UNKNOWN_KEY


def test_tampered_manifest_fails_signature(signer: Signer, verifier: Verifier) -> None:
    m = build_manifest(signer, "rag-corpus", [("a", H1), ("b", H2)])
    d = json.loads(m.to_json())
    d["count"] = 3
    forged = CollectionManifest.from_dict(d)
    assert verify_manifest(forged, verifier, [("a", H1), ("b", H2), ("c", H3)]).error is (
        ManifestError.SIGNATURE_INVALID
    )


def test_manifest_signature_is_domain_separated(signer: Signer) -> None:
    """A manifest signature must not be a valid pin signature and vice versa."""
    m = build_manifest(signer, "c", [("a", H1)])
    assert MANIFEST_DOMAIN_TAG != b"vectorpin/v2\x00"
    from cryptography.exceptions import InvalidSignature

    with pytest.raises(InvalidSignature):
        signer.public_key().verify(m.sig, m.canonical_payload())  # no tag -> invalid


def test_manifest_parse_rejections() -> None:
    base = {
        "v": 1,
        "collection_id": "c",
        "count": 1,
        "merkle_root": H1,
        "ts": "2026-05-05T12:00:00Z",
        "kid": "k",
        "sig": "A" * 86,
    }
    for bad in (
        {"v": 2},
        {"count": -1},
        {"count": 1.0},
        {"merkle_root": "md5:x"},
        {"ts": "2026-13-01T00:00:00Z"},
        {"collection_id": ""},
        {"sig": "A" * 86 + "=="},
        {"surprise": 1},
    ):
        with pytest.raises(ValueError):
            CollectionManifest.from_dict({**base, **bad})
    with pytest.raises(ValueError, match="too large"):
        CollectionManifest.from_json("x" * 70_000)
