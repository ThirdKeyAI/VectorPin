# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Chroma adapter.

Chroma's `metadatas` field accepts an arbitrary dict per record, which
is the cleanest possible home for a Pin. Both the in-process /
persistent client and the HTTP client expose the same `Collection`
interface, so this adapter works against either.

Chroma constrains metadata values to scalars (str, int, float, bool),
not nested dicts. We therefore serialize the Pin to JSON and store it
under a single string key — the key is shared across all backends so
operators can swap stores without rewriting metadata.

Install with: pip install 'vectorpin[chroma]'
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import numpy as np

from vectorpin.adapters.base import (
    PIN_METADATA_KEY,
    BaseAdapter,
    PinnedRecord,
    parse_pin_field,
    vector_from_store,
)
from vectorpin.attestation import Pin

if TYPE_CHECKING:
    from chromadb.api.models.Collection import Collection

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    h = host.strip("[]").lower()
    if h in _LOOPBACK_HOSTS:
        return True
    return h.startswith("127.")


def _enforce_tls(host: str, ssl: bool, headers: dict[str, str] | None) -> None:
    """Refuse to send auth headers over plaintext to a non-loopback host.

    Same contract as the Qdrant / Pinecone / pgvector adapters: a
    credential-bearing header over ``http://`` leaks the credential.
    ``VECTORPIN_ALLOW_INSECURE_HTTP=1`` is the environment-scoped
    escape hatch for trusted in-cluster overlays.
    """
    if not headers or ssl:
        return
    # Accept a bare hostname or a URL; only the host part matters.
    bare = host.split("://", 1)[1] if "://" in host else host
    bare = bare.split("/", 1)[0].rsplit(":", 1)[0] if not bare.startswith("[") else bare
    if _is_loopback(bare):
        return
    if os.environ.get("VECTORPIN_ALLOW_INSECURE_HTTP") == "1":
        return
    raise ValueError(
        "auth headers with non-TLS Chroma host refused "
        "(pass ssl=True, or set VECTORPIN_ALLOW_INSECURE_HTTP=1 if you know what you're doing)"
    )


class ChromaAdapter(BaseAdapter):
    """Wraps a Chroma collection for VectorPin reads and writes."""

    def __init__(self, collection: Collection):
        self._collection = collection

    @classmethod
    def connect_persistent(cls, path: str, collection_name: str) -> ChromaAdapter:
        """Open a Chroma collection backed by a local on-disk store."""
        try:
            import chromadb
        except ImportError as e:
            raise ImportError(
                "chromadb not installed. Run: pip install 'vectorpin[chroma]'"
            ) from e
        client = chromadb.PersistentClient(path=path)
        collection = client.get_collection(name=collection_name)
        return cls(collection)

    @classmethod
    def connect_http(
        cls,
        host: str,
        port: int,
        collection_name: str,
        *,
        ssl: bool = False,
        headers: dict[str, str] | None = None,
    ) -> ChromaAdapter:
        """Open a Chroma collection over the HTTP API.

        If ``headers`` carries credentials, the host must be loopback or
        ``ssl`` must be set; otherwise the connection is refused unless
        ``VECTORPIN_ALLOW_INSECURE_HTTP=1`` is set in the environment.
        """
        _enforce_tls(host, ssl, headers)
        try:
            import chromadb
        except ImportError as e:
            raise ImportError(
                "chromadb not installed. Run: pip install 'vectorpin[chroma]'"
            ) from e
        client = chromadb.HttpClient(host=host, port=port, ssl=ssl, headers=headers or {})
        collection = client.get_collection(name=collection_name)
        return cls(collection)

    def iter_records(self, *, batch_size: int = 256) -> Iterator[PinnedRecord]:
        # Chroma's `get()` returns the whole collection; we batch on
        # the Python side with offset/limit to bound memory. Note that
        # the modern client returns `embeddings` as a numpy ndarray, so
        # we cannot use truthy `or []` — use explicit None checks.
        offset = 0
        while True:
            page = self._collection.get(
                limit=batch_size,
                offset=offset,
                include=["embeddings", "metadatas"],
            )
            ids = list(page.get("ids") or [])
            if not ids:
                return
            embeddings = page.get("embeddings")
            if embeddings is None:
                embeddings = []
            metadatas = page.get("metadatas")
            if metadatas is None:
                metadatas = [None] * len(ids)
            for i, rid in enumerate(ids):
                yield self._build_record(rid, embeddings[i], metadatas[i])
            if len(ids) < batch_size:
                return
            offset += len(ids)

    def get(self, record_id: str) -> PinnedRecord:
        page = self._collection.get(
            ids=[record_id],
            include=["embeddings", "metadatas"],
        )
        ids = list(page.get("ids") or [])
        if not ids:
            raise KeyError(record_id)
        embeddings = page.get("embeddings")
        if embeddings is None:
            raise ValueError(f"chroma returned no embeddings for {record_id!r}")
        metadatas = page.get("metadatas")
        metadata = metadatas[0] if metadatas is not None else None
        return self._build_record(ids[0], embeddings[0], metadata)

    def attach_pin(self, record_id: str, pin: Pin) -> None:
        # Read-modify-write: Chroma's update replaces the metadata
        # dict, so we have to merge to preserve any other keys the
        # operator stored alongside the vector.
        existing = self._collection.get(ids=[record_id], include=["metadatas"])
        if not existing.get("ids"):
            raise KeyError(record_id)
        prior = (existing.get("metadatas") or [None])[0] or {}
        merged = dict(prior)
        merged[PIN_METADATA_KEY] = pin.to_json()
        self._collection.update(ids=[record_id], metadatas=[merged])

    # ---- internals ----

    def _build_record(self, rid: Any, embedding: Any, metadata: Any) -> PinnedRecord:
        if embedding is None:
            raise ValueError(
                f"record {rid!r} has no embedding; "
                "ensure include=['embeddings'] was passed and the collection has vectors"
            )
        # Chroma persists single-precision vectors (its HNSW index and
        # segment storage are float32). Depending on client version the
        # values come back as a float32 ndarray, a float64 ndarray, or a
        # list of Python floats; all carry the same float32 values, and
        # `vector_from_store` checks that the narrowing is exact.
        vector = vector_from_store(embedding, native_dtype=np.float32)
        meta = dict(metadata or {})
        pin, parse_error = parse_pin_field(meta.pop(PIN_METADATA_KEY, None))
        return PinnedRecord(
            id=str(rid), vector=vector, pin=pin, metadata=meta, parse_error=parse_error
        )
