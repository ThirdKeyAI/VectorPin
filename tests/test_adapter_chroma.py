# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""ChromaAdapter roundtrip tests.

Skipped automatically when `chromadb` is not installed. Uses Chroma's
persistent local client backed by a temp directory; no HTTP server is
required.
"""

from __future__ import annotations

import numpy as np
import pytest

chromadb = pytest.importorskip("chromadb")

from vectorpin import Signer, Verifier
from vectorpin.adapters import ChromaAdapter


@pytest.fixture
def chroma_collection(tmp_path):
    client = chromadb.PersistentClient(path=str(tmp_path / "chroma_db"))
    collection = client.create_collection(name="test")
    collection.add(
        ids=["a", "b"],
        embeddings=[[0.1] * 16, [0.2] * 16],
        metadatas=[{"source": "alpha"}, {"source": "beta"}],
    )
    return collection


def test_iter_records_returns_unpinned(chroma_collection):
    adapter = ChromaAdapter(chroma_collection)
    records = list(adapter.iter_records())
    assert {r.id for r in records} == {"a", "b"}
    assert all(r.pin is None for r in records)
    for r in records:
        assert r.vector.shape == (16,)
        assert r.metadata.get("source") in {"alpha", "beta"}


def test_attach_pin_and_get(chroma_collection):
    adapter = ChromaAdapter(chroma_collection)
    signer = Signer.generate(key_id="test-key")

    rec = adapter.get("a")
    pin = signer.pin(source="alpha", model="bench-model", vector=rec.vector)
    adapter.attach_pin("a", pin)

    refreshed = adapter.get("a")
    assert refreshed.pin is not None
    assert refreshed.pin.kid == "test-key"
    # Other metadata keys must survive the merge.
    assert refreshed.metadata.get("source") == "alpha"


def test_full_roundtrip_verifies(chroma_collection):
    adapter = ChromaAdapter(chroma_collection)
    signer = Signer.generate(key_id="test-key")
    verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})

    for record in adapter.iter_records():
        pin = signer.pin(
            source=str(record.metadata["source"]),
            model="bench-model",
            vector=record.vector,
        )
        adapter.attach_pin(record.id, pin)

    for record in adapter.iter_records():
        assert record.pin is not None
        result = verifier.verify(
            record.pin,
            source=str(record.metadata["source"]),
            vector=record.vector,
        )
        assert result, f"verify failed for {record.id}: {result.error}"


def test_get_missing_id_raises(chroma_collection):
    adapter = ChromaAdapter(chroma_collection)
    with pytest.raises(KeyError):
        adapter.get("nonexistent-id")


def test_tampered_vector_caught_after_pin(chroma_collection):
    adapter = ChromaAdapter(chroma_collection)
    signer = Signer.generate(key_id="test-key")
    verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})

    rec = adapter.get("a")
    pin = signer.pin(source="alpha", model="bench-model", vector=rec.vector)
    adapter.attach_pin("a", pin)

    refreshed = adapter.get("a")
    tampered = refreshed.vector.copy()
    tampered[0] = float(np.float32(tampered[0]) + np.float32(1e-3))
    result = verifier.verify(refreshed.pin, source="alpha", vector=tampered)
    assert not result
    assert result.error.value == "vector_tampered"


# ---- VP-15: TLS guard for the HTTP client -----------------------------------


def test_connect_http_refuses_auth_headers_over_plaintext(monkeypatch):
    monkeypatch.delenv("VECTORPIN_ALLOW_INSECURE_HTTP", raising=False)
    with pytest.raises(ValueError, match="non-TLS"):
        ChromaAdapter.connect_http(
            host="chroma.internal.example",
            port=8000,
            collection_name="c",
            ssl=False,
            headers={"Authorization": "Bearer secret"},
        )


def test_connect_http_allows_headers_over_loopback_or_ssl(monkeypatch):
    """Guard passes; the connection itself then fails because nothing
    is listening — that failure must come from chromadb, not the guard."""
    monkeypatch.delenv("VECTORPIN_ALLOW_INSECURE_HTTP", raising=False)
    from vectorpin.adapters.chroma import _enforce_tls

    _enforce_tls("localhost", False, {"Authorization": "x"})
    _enforce_tls("127.0.0.1", False, {"Authorization": "x"})
    _enforce_tls("http://127.0.0.1:8000", False, {"Authorization": "x"})
    _enforce_tls("chroma.internal.example", True, {"Authorization": "x"})
    _enforce_tls("chroma.internal.example", False, None)
    with pytest.raises(ValueError):
        _enforce_tls("http://chroma.internal.example:8000", False, {"Authorization": "x"})
    monkeypatch.setenv("VECTORPIN_ALLOW_INSECURE_HTTP", "1")
    _enforce_tls("chroma.internal.example", False, {"Authorization": "x"})


def test_stripped_pin_is_parse_error_not_unpinned(chroma_collection):
    adapter = ChromaAdapter(chroma_collection)
    chroma_collection.update(ids=["a"], metadatas=[{"source": "alpha", "vectorpin": ""}])
    rec = adapter.get("a")
    assert rec.pin is None
    assert rec.parse_error is not None
