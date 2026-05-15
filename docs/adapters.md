# Vector Store Adapters

VectorPin ships thin adapters for the major vector databases. Adapters do two things:

1. **Walk records** — Iterate the collection yielding `(id, vector, metadata, pin)` tuples for verification.
2. **Attach pins** — Write a pin into the record's metadata in whichever shape the backend prefers.

The adapter protocol lives at [`src/vectorpin/adapters/base.py`](https://github.com/ThirdKeyAI/VectorPin/blob/main/src/vectorpin/adapters/base.py) and is intentionally thin. Community contributions for new backends are welcome.

---

## Status

| Backend | Status | Install | Notes |
|---|---|---|---|
| LanceDB *(default)* | Alpha | `pip install 'vectorpin[default]'` | Embedded, file-based, no daemon. Recommended. |
| Chroma | Alpha | `pip install 'vectorpin[chroma]'` | Both persistent and HTTP modes. |
| Qdrant | Alpha | `pip install 'vectorpin[qdrant]'` | Server-side payload filtering. |
| Pinecone | Alpha | `pip install 'vectorpin[pinecone]'` | Hosted only. |
| pgvector | Planned | — | |
| FAISS | Planned | Use `LanceDBAdapter` (embedded, has metadata column natively). | |

All adapters present the same `iter_records()` / `attach_pin()` interface. The backend differences are limited to where the pin physically lives in the underlying record.

---

## Storage Convention

By convention, pins are stored under the metadata key `vectorpin`. Specifically:

| Backend | Pin lives at |
|---|---|
| LanceDB | A typed schema column literally named `vectorpin` (string-valued, holding the pin JSON). |
| Chroma | The `metadata` dict, under key `vectorpin`. |
| Qdrant | The `payload` dict, under key `vectorpin`. |
| Pinecone | The `metadata` dict, under key `vectorpin`. |

Backends without free-form metadata fields are out of scope — provenance must travel with the data, not in a sidecar.

---

## LanceDB (default)

LanceDB is the recommended default: embedded, file-based, no daemon, with a typed schema column that holds the Pin natively. It matches the [Symbiont runtime's](https://github.com/thirdkeyai/symbiont) default vector backend.

### Pin a corpus

```python
from vectorpin import Signer
from vectorpin.adapters import LanceDBAdapter

adapter = LanceDBAdapter.connect("./data/vector_db", "rag-corpus")
signer = Signer.generate(key_id="prod-2026-05")

for record in adapter.iter_records():
    pin = signer.pin(
        source=record.metadata["text"],
        model="text-embedding-3-large",
        vector=record.vector,
    )
    adapter.attach_pin(record.id, pin)
```

### Verify a corpus

```python
from vectorpin import Verifier
from vectorpin.adapters import LanceDBAdapter

adapter = LanceDBAdapter.connect("./data/vector_db", "rag-corpus")
verifier = Verifier({"prod-2026-05": public_key_bytes})

failed = 0
for record in adapter.iter_records():
    if record.pin is None:
        continue
    result = verifier.verify(
        record.pin,
        source=record.metadata["text"],
        vector=record.vector,
    )
    if not result.ok:
        print(f"FAIL {record.id} [{result.error.value}] {result.detail}")
        failed += 1

assert failed == 0, f"{failed} records failed verification"
```

### Connection options

`LanceDBAdapter.connect` accepts a URI (directory path, `s3://`, `gs://`, or LanceDB Cloud connection string), a table name, and optional column overrides:

```python
adapter = LanceDBAdapter.connect(
    uri="s3://my-bucket/vector_db",
    table_name="rag-corpus",
    id_column="id",         # default: "id"
    vector_column="vector", # default: "vector"
)
```

### Symbiont schema

For Symbiont deployments: Symbiont's source text lives in the `content` column. Symbiont's column literally named `source` is upstream provenance (a URL), not VectorPin's `source` argument. Pass `source=record.metadata["content"]` when calling `signer.pin`. See [`tests/test_adapter_lancedb_symbiont.py`](https://github.com/ThirdKeyAI/VectorPin/blob/main/tests/test_adapter_lancedb_symbiont.py) for an end-to-end example.

---

## Chroma

Chroma offers both an embedded persistent client and a remote HTTP client. The adapter supports both.

### Persistent (embedded)

```python
from vectorpin.adapters import ChromaAdapter

adapter = ChromaAdapter.connect_persistent("./chroma_db", "my-rag")
```

### HTTP

```python
adapter = ChromaAdapter.connect_http(
    host="chroma.internal",
    port=8000,
    collection_name="my-rag",
    ssl=False,
)
```

### Pinning

```python
for record in adapter.iter_records():
    pin = signer.pin(
        source=record.metadata["text"],
        model="text-embedding-3-large",
        vector=record.vector,
    )
    adapter.attach_pin(record.id, pin)
```

The pin is stored as a JSON string under `metadata["vectorpin"]`. Chroma metadata is `dict[str, str | int | float | bool]`, so the pin survives the JSON-string round trip without loss.

---

## Qdrant

Qdrant supports both local and Qdrant Cloud deployments. Pins are written into the `payload` dict.

```python
from vectorpin.adapters import QdrantAdapter

adapter = QdrantAdapter.connect(
    url="http://localhost:6333",
    collection_name="my-rag",
    api_key=None,   # set for Qdrant Cloud
)

for record in adapter.iter_records(batch_size=256):
    pin = signer.pin(
        source=record.metadata["text"],
        model="text-embedding-3-large",
        vector=record.vector,
    )
    adapter.attach_pin(record.id, pin)
```

Qdrant's payload filtering means you can query for unpinned records server-side:

```python
# Pseudo — exact API depends on qdrant-client version
unpinned = client.scroll(
    collection_name="my-rag",
    scroll_filter={"must_not": [{"key": "vectorpin", "match": {"any": ["*"]}}]},
)
```

---

## Pinecone

Pinecone is hosted-only. Pins are stored under `metadata["vectorpin"]` as a JSON string.

```python
from vectorpin.adapters import PineconeAdapter

adapter = PineconeAdapter.connect(
    api_key="...",
    index_name="my-rag",
)

for record in adapter.iter_records():
    pin = signer.pin(
        source=record.metadata["text"],
        model="text-embedding-3-large",
        vector=record.vector,
    )
    adapter.attach_pin(record.id, pin)
```

Pinecone metadata values are size-limited (40 KiB per record). VectorPin pins are well under 1 KiB at typical sizes, so you'll never hit the limit — but if you stuff large `extra` payloads in, double-check.

---

## Choosing a Backend

| If you... | Use |
|---|---|
| Just want pinning without standing up a server | **LanceDB** (default) |
| Already run Chroma | Chroma |
| Need server-side payload filtering | Qdrant |
| Are on Pinecone today | Pinecone |
| Run Symbiont | LanceDB (matches Symbiont's default backend) |

LanceDB also gives you a typed `vectorpin` column, which is more grep-able than a JSON blob in a metadata dict — useful when reasoning about partial backfills.

---

## Writing a New Adapter

The adapter protocol is two methods plus a record dataclass. Sketch:

```python
from dataclasses import dataclass
from typing import Iterator
import numpy as np
from vectorpin import Pin

@dataclass
class PinnedRecord:
    id: str
    vector: np.ndarray
    metadata: dict
    pin: Pin | None

class MyBackendAdapter:
    @classmethod
    def connect(cls, ...) -> "MyBackendAdapter":
        ...

    def iter_records(self, batch_size: int = 256) -> Iterator[PinnedRecord]:
        ...

    def attach_pin(self, record_id: str, pin: Pin) -> None:
        ...
```

See [`src/vectorpin/adapters/base.py`](https://github.com/ThirdKeyAI/VectorPin/blob/main/src/vectorpin/adapters/base.py) for the canonical protocol and the existing adapters for working examples.

---

## See Also

- [CLI Guide](cli-guide.md#audit-commands) — Command-line equivalents to programmatic auditing
- [Getting Started](getting-started.md) — End-to-end pinning + verification walkthrough
- [Pin Protocol](pin-protocol.md) — Wire format and verification order
