# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Pinecone adapter.

Targets the v5+ Pinecone Python client (`pip install pinecone`).
The package was renamed from `pinecone-client` in 2024; this adapter
uses the new name. The pin lives in the index's metadata field;
Pinecone caps metadata at 40 KB per vector, which is comfortably
above the ~500 byte JSON form a Pin produces.

Pinecone is cloud-only — there is no embedded mode — so this adapter
makes one HTTP round-trip per `get` and one per `attach_pin`. The
test for this adapter is gated on `PINECONE_API_KEY` being present in
the environment; no live calls are made in unit tests.

Install with: pip install 'vectorpin[pinecone]'
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import numpy as np

from vectorpin.adapters.base import PIN_METADATA_KEY, BaseAdapter, PinnedRecord
from vectorpin.attestation import Pin

if TYPE_CHECKING:
    from pinecone import Index


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    h = host.strip("[]").lower()
    if h in _LOOPBACK_HOSTS:
        return True
    return h.startswith("127.")


def _enforce_tls_host(host: str | None, api_key: str | None) -> None:
    """Refuse plaintext HTTP when an api_key is present.

    Pinecone's `host` may be a bare hostname (recommended) or a full
    URL. Only the URL form lets us see a scheme; if a scheme is set to
    http and the host isn't loopback we treat that as misconfiguration.
    Set VECTORPIN_ALLOW_INSECURE_HTTP=1 to override.
    """
    if not host or not api_key:
        return
    parsed = urlparse(host)
    # `urlparse("example.com")` gives scheme="" and netloc="" — nothing
    # to validate against, fall through.
    if not parsed.scheme:
        return
    if parsed.scheme != "http":
        return
    if _is_loopback(parsed.hostname):
        return
    if os.environ.get("VECTORPIN_ALLOW_INSECURE_HTTP") == "1":
        return
    raise ValueError(
        "api_key with non-TLS URL refused "
        "(set VECTORPIN_ALLOW_INSECURE_HTTP=1 if you know what you're doing)"
    )


class PineconeAdapter(BaseAdapter):
    """Wraps a Pinecone index for VectorPin reads and writes."""

    def __init__(self, index: Index, *, namespace: str | None = None):
        self._index = index
        self._namespace = namespace

    @classmethod
    def connect(
        cls,
        api_key: str,
        index_name: str,
        *,
        namespace: str | None = None,
        host: str | None = None,
    ) -> PineconeAdapter:
        """Open an index against Pinecone Cloud.

        `host` is optional but recommended for production: passing
        the dedicated index host skips a control-plane lookup on
        every connection.

        If `host` is provided as a URL with scheme `http://`, we refuse
        the connection unless the host is loopback. Set the env var
        `VECTORPIN_ALLOW_INSECURE_HTTP=1` to override; this exists for
        cases where transport security is enforced out-of-band.
        """
        _enforce_tls_host(host, api_key)
        try:
            from pinecone import Pinecone
        except ImportError as e:
            raise ImportError(
                "pinecone-client not installed. Run: pip install 'vectorpin[pinecone]'"
            ) from e
        pc = Pinecone(api_key=api_key)
        index = pc.Index(name=index_name, host=host) if host else pc.Index(index_name)
        return cls(index, namespace=namespace)

    def iter_records(self, *, batch_size: int = 100) -> Iterator[PinnedRecord]:
        """Yield every record in the index (or namespace).

        Pinecone's `list` returns ids in pages; `fetch` then retrieves
        vectors + metadata for each page. Iteration is therefore
        2 * (corpus_size / batch_size) round-trips.
        """
        kwargs: dict[str, Any] = {"limit": batch_size}
        if self._namespace is not None:
            kwargs["namespace"] = self._namespace
        for page in self._index.list(**kwargs):
            ids = list(page) if isinstance(page, list) else [page]
            if not ids:
                continue
            fetched = self._fetch_many(ids)
            for rid in ids:
                if rid in fetched:
                    yield self._record_from_fetch(rid, fetched[rid])

    def get(self, record_id: str) -> PinnedRecord:
        fetched = self._fetch_many([record_id])
        if record_id not in fetched:
            raise KeyError(record_id)
        return self._record_from_fetch(record_id, fetched[record_id])

    def attach_pin(self, record_id: str, pin: Pin) -> None:
        kwargs: dict[str, Any] = {
            "id": record_id,
            "set_metadata": {PIN_METADATA_KEY: pin.to_json()},
        }
        if self._namespace is not None:
            kwargs["namespace"] = self._namespace
        self._index.update(**kwargs)

    # ---- internals ----

    def _fetch_many(self, ids: list[str]) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"ids": ids}
        if self._namespace is not None:
            kwargs["namespace"] = self._namespace
        resp = self._index.fetch(**kwargs)
        # The v3 client returns a FetchResponse with a `vectors` dict.
        vectors = getattr(resp, "vectors", None)
        if vectors is None and isinstance(resp, dict):
            vectors = resp.get("vectors", {})
        return vectors or {}

    def _record_from_fetch(self, rid: str, payload: Any) -> PinnedRecord:
        # `payload` is either a Vector dataclass (v3+) or a dict.
        # Handle dicts first because `getattr(dict, "values")` would
        # return the dict.values *method* and silently mask the issue.
        if isinstance(payload, dict):
            values = payload.get("values")
            metadata = payload.get("metadata")
        else:
            values = getattr(payload, "values", None)
            metadata = getattr(payload, "metadata", None)
        if values is None:
            raise ValueError(f"record {rid!r} returned no values; was the index queried correctly?")
        vector = np.asarray(values, dtype=np.float32)
        if vector.ndim != 1:
            raise ValueError(f"record {rid!r} returned non-1D values shape {vector.shape}")
        meta = dict(metadata or {})
        pin_payload = meta.pop(PIN_METADATA_KEY, None)
        pin = Pin.from_json(pin_payload) if pin_payload else None
        return PinnedRecord(id=str(rid), vector=vector, pin=pin, metadata=meta)
