# VectorPin CLI Guide

The VectorPin CLI (`vectorpin`) provides commands for key generation, single-pin demos, and bulk auditing of vector-store collections. It ships with the Python package.

---

## Installation

```bash
pip install vectorpin

# Or, if you'll audit a specific backend, pull its driver too:
pip install 'vectorpin[default]'    # LanceDB
pip install 'vectorpin[chroma]'
pip install 'vectorpin[qdrant]'
pip install 'vectorpin[pinecone]'
```

Confirm the install:

```bash
vectorpin --help
```

---

## Commands

| Command | Purpose |
|---|---|
| `vectorpin keygen` | Generate an Ed25519 signing key pair. |
| `vectorpin pin` | Sign a single `(text, vector)` pair (debug / demo). |
| `vectorpin verify-pin` | Verify a single Pin against ground-truth source / vector. |
| `vectorpin audit-lancedb` | Walk a LanceDB table and verify every pinned record. |
| `vectorpin audit-chroma` | Walk a Chroma collection and verify every pinned record. |
| `vectorpin audit-qdrant` | Walk a Qdrant collection and verify every pinned record. |

---

### `vectorpin keygen` — Generate Key Pair

Generate an Ed25519 key pair for signing pins.

```bash
vectorpin keygen --key-id prod-2026-05 --output ./keys
```

**Options:**

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--key-id` | Yes | — | Identifier for the new key (travels in the pin's `kid` field). |
| `--output` | No | `keys` | Output directory. Created if missing. |

**Output files:**

```
keys/
├── prod-2026-05.priv   # Ed25519 private key, 32 bytes — KEEP SECRET
└── prod-2026-05.pub    # Ed25519 public key,  32 bytes
```

Set restrictive permissions on the private key immediately:

```bash
chmod 600 ./keys/prod-2026-05.priv
```

---

### `vectorpin pin` — Sign a Single Pair

Sign one `(source, vector)` pair and print the pin JSON to stdout. Intended for demos and one-off integrations; production ingestion should use a [vector store adapter](adapters.md) so the pin is written next to the embedding atomically.

```bash
vectorpin pin \
  --private-key ./keys/prod-2026-05.priv \
  --key-id prod-2026-05 \
  --model text-embedding-3-large \
  --source ./doc.txt \
  --vector ./embedding.npy
```

**Options:**

| Flag | Required | Description |
|------|----------|-------------|
| `--private-key` | Yes | Path to `.priv` key file. |
| `--key-id` | Yes | Key identifier (written into the pin's `kid` field). |
| `--model` | Yes | Embedding model identifier (e.g., `text-embedding-3-large`). |
| `--source` | Yes | Path to UTF-8 source-text file. |
| `--vector` | Yes | Path to vector file: `.npy` (NumPy) or `.json` (array of floats). |

**Output:** Compact pin JSON to stdout; pipe to a file or directly into your DB write path.

---

### `vectorpin verify-pin` — Verify a Single Pin

Verify one pin against ground-truth source and/or vector. Both ground-truth inputs are optional — omit them to check only the signature (i.e., that the pin was produced by the registered key).

```bash
vectorpin verify-pin \
  --public-key ./keys/prod-2026-05.pub \
  --key-id prod-2026-05 \
  --pin ./pin.json \
  --source ./doc.txt \
  --vector ./embedding.npy
```

**Options:**

| Flag | Required | Description |
|------|----------|-------------|
| `--public-key` | Yes | Path to `.pub` key file. |
| `--key-id` | Yes | Key identifier (must match the pin's `kid`). |
| `--pin` | Yes | Path to pin JSON. |
| `--source` | No | Path to source text. If set, source is verified against `source_hash`. |
| `--vector` | No | Path to vector. If set, vector is verified against `vec_hash`. |

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | `OK` — pin verified. |
| `2` | Failure. Reason printed to stderr in the form `FAIL [<error>] <detail>`. |

---

## Audit Commands

Audit commands walk an entire collection, verify every pinned record, and print a JSON summary to stdout. They exit non-zero if any pinned record fails verification — so they compose cleanly into CI or cron.

Common audit summary shape:

```json
{
  "table": "rag-corpus",
  "total": 12453,
  "pinned": 12450,
  "verified_ok": 12450,
  "verification_failed": 0,
  "unpinned": 3
}
```

`unpinned` records are reported but do **not** by themselves fail the run — operators who want stricter behavior can `grep` `unpinned` from the JSON summary in CI.

### `vectorpin audit-lancedb`

Audit a LanceDB table. The recommended default backend.

```bash
vectorpin audit-lancedb \
  --uri ./data/vector_db \
  --table rag-corpus \
  --public-key ./keys/prod-2026-05.pub \
  --key-id prod-2026-05 \
  --source-column text
```

**Options:**

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--uri` | Yes | — | LanceDB URI: a directory, `s3://`, `gs://`, or LanceDB Cloud connection string. |
| `--table` | Yes | — | Table name. |
| `--public-key` | Yes | — | Path to `.pub` key. |
| `--key-id` | Yes | — | Key identifier. |
| `--id-column` | No | `id` | Column holding the record id. |
| `--vector-column` | No | `vector` | Column holding the embedding. |
| `--source-column` | No | — | Optional column holding the source text; if set, source is verified too. For Symbiont's default schema, use `--source-column content`. |
| `--batch-size` | No | `256` | Records per batch. |

### `vectorpin audit-chroma`

Audit a Chroma collection (persistent or HTTP).

```bash
# Persistent (file-based)
vectorpin audit-chroma \
  --path ./chroma_db \
  --collection my-rag \
  --public-key ./keys/prod-2026-05.pub \
  --key-id prod-2026-05 \
  --source-metadata-key text

# HTTP server
vectorpin audit-chroma \
  --host chroma.internal \
  --port 8000 \
  --collection my-rag \
  --public-key ./keys/prod-2026-05.pub \
  --key-id prod-2026-05
```

**Options:**

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--collection` | Yes | — | Collection name. |
| `--public-key` | Yes | — | Path to `.pub` key. |
| `--key-id` | Yes | — | Key identifier. |
| `--path` | One of | — | Path for a `PersistentClient`. |
| `--host` | One of | — | Host for an `HttpClient`. (Either `--path` or `--host` is required.) |
| `--port` | No | `8000` | HTTP port. |
| `--ssl` | No | off | Enable TLS for HTTP client. |
| `--source-metadata-key` | No | — | Optional metadata key holding the source text. |
| `--batch-size` | No | `256` | Records per batch. |

### `vectorpin audit-qdrant`

Audit a Qdrant collection.

```bash
vectorpin audit-qdrant \
  --url http://localhost:6333 \
  --collection my-rag \
  --public-key ./keys/prod-2026-05.pub \
  --key-id prod-2026-05
```

**Options:**

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--url` | Yes | — | Qdrant URL, e.g. `http://localhost:6333`. |
| `--collection` | Yes | — | Collection name. |
| `--public-key` | Yes | — | Path to `.pub` key. |
| `--key-id` | Yes | — | Key identifier. |
| `--api-key` | No | — | API key for Qdrant Cloud. |
| `--source-payload-key` | No | — | Optional payload key holding source text; if set, source is verified too. |
| `--batch-size` | No | `256` | Records per batch. |

---

## CI Recipes

### Drop-in cron audit

```bash
#!/usr/bin/env bash
set -euo pipefail

vectorpin audit-lancedb \
  --uri "$VECTOR_DB_URI" \
  --table "$VECTOR_TABLE" \
  --public-key "$VECTORPIN_PUB" \
  --key-id "$VECTORPIN_KID" \
  --source-column text \
  > /var/log/vectorpin/$(date +%Y-%m-%dT%H:%M).json
```

Non-zero exit triggers your alerting; the JSON summary is the audit log.

### GitHub Actions

```yaml
- name: VectorPin audit
  run: |
    pip install 'vectorpin[default]'
    vectorpin audit-lancedb \
      --uri "${{ secrets.VECTOR_DB_URI }}" \
      --table rag-corpus \
      --public-key ./keys/prod-2026-05.pub \
      --key-id prod-2026-05 \
      --source-column text
```

### Treat unpinned records as failures

The audit commands tolerate unpinned records by design (migrations, partial backfills). To fail closed:

```bash
summary=$(vectorpin audit-lancedb --uri ./db --table t --public-key ./k.pub --key-id k)
echo "$summary"
echo "$summary" | python -c "import json,sys; s=json.load(sys.stdin); sys.exit(1 if s['unpinned'] else 0)"
```

---

## See Also

- [Getting Started](getting-started.md) — Library usage in Python, Rust, and TypeScript
- [Vector Store Adapters](adapters.md) — Programmatic equivalents to the `audit-*` commands
- [Deployment](deployment.md) — Where to keep keys, how to rotate them
