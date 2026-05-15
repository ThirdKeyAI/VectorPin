# Getting Started with VectorPin

This guide walks you through installing VectorPin, generating a signing key, pinning your first embedding, and verifying it — in Python, Rust, and TypeScript.

---

## Installation

### Python

Requires Python >= 3.11.

```bash
# Core library only (no vector DB driver)
pip install vectorpin

# With the default LanceDB adapter (recommended)
pip install 'vectorpin[default]'

# Other adapters
pip install 'vectorpin[chroma]'
pip install 'vectorpin[qdrant]'
pip install 'vectorpin[pinecone]'

# Statistical detectors
pip install 'vectorpin[detectors]'

# Everything
pip install 'vectorpin[all]'
```

### Rust

Add `vectorpin` to your `Cargo.toml`:

```toml
[dependencies]
vectorpin = "0.1"
```

Build and test:

```bash
cd rust && cargo build && cargo test
```

### TypeScript / JavaScript

Requires Node.js >= 20. Pure JavaScript dependencies (`@noble/ed25519`, `@noble/hashes`) — also runs on Deno, Bun, and edge runtimes.

```bash
npm install vectorpin
```

### CLI

The CLI ships with the Python package:

```bash
pip install vectorpin
vectorpin --help
```

---

## Step 1: Generate a Signing Key

VectorPin uses **Ed25519** exclusively. Generate a keypair in any language:

### Python

```python
from vectorpin import Signer

signer = Signer.generate(key_id="prod-2026-05")
private_bytes = signer.private_key_bytes()   # KEEP SECRET
public_bytes = signer.public_key_bytes()
```

### Rust

```rust
use vectorpin::Signer;

let signer = Signer::generate("prod-2026-05".to_string());
let private_bytes = signer.private_key_bytes();   // KEEP SECRET
let public_bytes = signer.public_key_bytes();
```

### TypeScript

```ts
import { Signer } from 'vectorpin';

const signer = Signer.generate('prod-2026-05');
const privateBytes = signer.privateKeyBytes();   // KEEP SECRET
const publicBytes = signer.publicKeyBytes();
```

### CLI

```bash
vectorpin keygen --key-id prod-2026-05 --output ./keys
```

This writes two files:

- `keys/prod-2026-05.priv` — Ed25519 private key (32 bytes, `0600` permissions recommended)
- `keys/prod-2026-05.pub` — Ed25519 public key (32 bytes)

The `kid` is the only label that travels with the pin — pick something stable and rotatable (see the [naming convention](security.md#key-id-naming-convention)).

---

## Step 2: Pin an Embedding

A Pin is a compact JSON attestation that commits to the source text, the producing model, the vector itself, and the timestamp. It is Ed25519-signed and travels alongside the embedding in your vector DB.

### Python

```python
import numpy as np
from vectorpin import Signer

signer = Signer.generate(key_id="prod-2026-05")
embedding = my_model.embed("The quick brown fox.")  # np.ndarray[f32]

pin = signer.pin(
    source="The quick brown fox.",
    model="text-embedding-3-large",
    vector=embedding,
)

print(pin.to_json())
# Store this string in your vector DB metadata, keyed as "vectorpin".
```

### Rust

```rust
use vectorpin::Signer;

let signer = Signer::generate("prod-2026-05".to_string());
let embedding: Vec<f32> = my_model_embed("The quick brown fox.");

let pin = signer.pin(
    "The quick brown fox.",
    "text-embedding-3-large",
    embedding.as_slice(),
)?;

let json = pin.to_json()?;
```

### TypeScript

```ts
import { Signer } from 'vectorpin';

const signer = Signer.generate('prod-2026-05');
const embedding = new Float32Array(/* ... 3072 floats ... */);

const pin = signer.pin({
  source: 'The quick brown fox.',
  model: 'text-embedding-3-large',
  vector: embedding,
});

const json = pin.toJSON();
```

### CLI

```bash
vectorpin pin \
  --private-key ./keys/prod-2026-05.priv \
  --key-id prod-2026-05 \
  --model text-embedding-3-large \
  --source ./doc.txt \
  --vector ./embedding.npy
```

The pin JSON is printed to stdout. Pipe to a file or directly into your DB write path.

### Pin Structure

```json
{
  "v": 2,
  "kid": "prod-2026-05",
  "model": "text-embedding-3-large",
  "source_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "vec_hash": "sha256:0123abcd...",
  "vec_dtype": "f32",
  "vec_dim": 3072,
  "ts": "2026-05-15T12:00:00Z",
  "sig": "MEUCIQD..."
}
```

See [Pin Protocol](pin-protocol.md) for the full wire-format specification.

---

## Step 3: Verify a Pin

Verification distinguishes failure modes so callers can route them differently — a `VECTOR_TAMPERED` is a security incident; an `UNKNOWN_KEY` is usually a misconfiguration.

### Python

```python
from vectorpin import Pin, Verifier

verifier = Verifier({"prod-2026-05": signer.public_key_bytes()})

result = verifier.verify(
    pin,
    source="The quick brown fox.",   # ground-truth source
    vector=embedding,                # ground-truth vector
)

if result.ok:
    print("Pin verified.")
else:
    print(f"FAIL [{result.error.value}] {result.detail}")
```

### Rust

```rust
use vectorpin::Verifier;

let mut verifier = Verifier::new();
verifier.add_key(signer.key_id(), signer.public_key_bytes());

let result = verifier.verify_full::<&[f32]>(
    &pin,
    Some("The quick brown fox."),
    Some(embedding.as_slice()),
    None,
);
assert!(result.is_ok());
```

### TypeScript

```ts
import { Verifier } from 'vectorpin';

const verifier = new Verifier({ [signer.keyId]: signer.publicKeyBytes() });

const result = verifier.verify(pin, {
  source: 'The quick brown fox.',
  vector: embedding,
});

if (!result.ok) throw new Error(`integrity failure: ${result.error}`);
```

### CLI

```bash
vectorpin verify-pin \
  --public-key ./keys/prod-2026-05.pub \
  --key-id prod-2026-05 \
  --pin ./pin.json \
  --source ./doc.txt \
  --vector ./embedding.npy
```

Exit code 0 on success, 2 on failure. The failure reason is printed to stderr.

### Verification Outcomes

| Outcome | Meaning |
|---|---|
| `OK` | Signature valid, vector intact, source matches. |
| `SIGNATURE_INVALID` | Pin was forged or re-signed by an attacker. |
| `VECTOR_TAMPERED` | Embedding modified after pinning. **This is the steganography kill shot.** |
| `SOURCE_MISMATCH` | Source text differs from what was pinned. |
| `MODEL_MISMATCH` | Pin was produced by a different embedding model than expected. |
| `UNKNOWN_KEY` | Pin signed by a key not in the verifier's registry. |
| `KEY_EXPIRED` | `ts` falls outside the registered key's `(valid_from, valid_until)` window. |
| `SHAPE_MISMATCH` | Supplied vector dimensionality does not match `vec_dim`. |
| `PARSE_ERROR` | Pin JSON is malformed, oversized, or contains unknown top-level fields. |
| `RECORD_MISMATCH` / `COLLECTION_MISMATCH` / `TENANT_MISMATCH` | Replay-protection mismatch (see [Pin Protocol §8](pin-protocol.md#replay-protection)). |

---

## Step 4: Pin a Whole Corpus

Most users don't pin one vector at a time — they pin during ingestion and verify during audit. Use a [vector store adapter](adapters.md) to do this without writing schema code:

```python
from vectorpin import Signer, Verifier
from vectorpin.adapters import LanceDBAdapter

adapter = LanceDBAdapter.connect("./data/vector_db", "rag-corpus")
signer = Signer.generate(key_id="prod-2026-05")

# Pin during ingestion
for record in adapter.iter_records():
    pin = signer.pin(
        source=record.metadata["text"],   # column holding source text
        model="text-embedding-3-large",
        vector=record.vector,
    )
    adapter.attach_pin(record.id, pin)
```

Then audit from the command line as often as you like:

```bash
vectorpin audit-lancedb \
  --uri ./data/vector_db \
  --table rag-corpus \
  --public-key ./keys/prod-2026-05.pub \
  --key-id prod-2026-05 \
  --source-column text
```

JSON summary on stdout, non-zero exit on any failure — drops into CI or cron unchanged. See [CLI Guide](cli-guide.md#audit-commands) for the audit commands across all backends.

---

## Next Steps

- [Pin Protocol](pin-protocol.md) — Wire format and verification order
- [CLI Guide](cli-guide.md) — Full CLI reference
- [Vector Store Adapters](adapters.md) — LanceDB, Chroma, Qdrant, Pinecone
- [Statistical Detectors](detectors.md) — Defense-in-depth against ingestion-time poisoning
- [Deployment](deployment.md) — Key custody, rotation, CI integration
- [Security](security.md) — Threat model and best practices
