# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Vector database adapters.

Each adapter knows how to read pins from a specific store's metadata
field and feed them through the Verifier. Adapters are intentionally
thin — they do not own verification policy, only marshalling.

Backend client libraries are optional installs. The adapter classes
are imported lazily through ``__getattr__`` so that
``from vectorpin.adapters import LanceDBAdapter`` does not pull in
chromadb, pinecone-client, or qdrant-client just because the user
wants one of them. The dependency only has to be present when the
adapter is actually used.

Recommended default: :class:`LanceDBAdapter` (embedded, no daemon,
matches Symbiont's default vector backend). Install with
``pip install 'vectorpin[default]'``.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from vectorpin.adapters.base import PIN_METADATA_KEY, BaseAdapter, PinnedRecord

if TYPE_CHECKING:
    from vectorpin.adapters.chroma import ChromaAdapter
    from vectorpin.adapters.lancedb import LanceDBAdapter
    from vectorpin.adapters.pgvector import PgVectorAdapter
    from vectorpin.adapters.pinecone import PineconeAdapter
    from vectorpin.adapters.qdrant import QdrantAdapter

__all__ = [
    "PIN_METADATA_KEY",
    "BaseAdapter",
    "ChromaAdapter",
    "LanceDBAdapter",
    "PgVectorAdapter",
    "PineconeAdapter",
    "PinnedRecord",
    "QdrantAdapter",
]

_LAZY_ADAPTERS = {
    "ChromaAdapter": ("vectorpin.adapters.chroma", "ChromaAdapter"),
    "LanceDBAdapter": ("vectorpin.adapters.lancedb", "LanceDBAdapter"),
    "PgVectorAdapter": ("vectorpin.adapters.pgvector", "PgVectorAdapter"),
    "PineconeAdapter": ("vectorpin.adapters.pinecone", "PineconeAdapter"),
    "QdrantAdapter": ("vectorpin.adapters.qdrant", "QdrantAdapter"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY_ADAPTERS.get(name)
    if target is None:
        raise AttributeError(f"module 'vectorpin.adapters' has no attribute {name!r}")
    module_name, attr_name = target
    module = importlib.import_module(module_name)
    return getattr(module, attr_name)
