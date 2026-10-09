# VectorPin

**Verifiable integrity for AI embedding stores.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Rust stable](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Node 20+](https://img.shields.io/badge/node-20+-green.svg)](https://nodejs.org/)
[![Status: beta](https://img.shields.io/badge/status-beta-yellow.svg)](#status)
[![Docs](https://img.shields.io/badge/docs-docs.vectorpin.org-8a3a72.svg)](https://docs.vectorpin.org/)
[![arXiv](https://img.shields.io/badge/arXiv-2605.13764-b31b1b.svg)](https://arxiv.org/abs/2605.13764)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20058256.svg)](https://doi.org/10.5281/zenodo.20058256)

Vector databases are the new soft underbelly of the AI stack. Models trust them. Agents query them. Compliance audits don't yet ask about them. VectorPin pins every embedding to its source content and the model that produced it, then lets you verify — on every read through the adapter read wrappers, and on a schedule through the audit CLI — that nothing in the store has changed since it was signed, including covert steganographic modifications invisible to traditional DLP.

**[Documentation: docs.vectorpin.org](https://docs.vectorpin.org/)** · [arXiv preprint](https://arxiv.org/abs/2605.13764) · [Source: github.com/ThirdKeyAI/VectorPin](https://github.com/ThirdKeyAI/VectorPin)

Part of the [ThirdKey](https://thirdkey.ai) Trust Stack, alongside [Symbiont](https://github.com/ThirdKeyAI/Symbiont) (policy-governed agent runtime) and [SchemaPin](https://github.com/ThirdKeyAI/SchemaPin) (cryptographic tool verification).

## Why this matters

Modern RAG systems convert sensitive content into high-dimensional vectors and store them in databases that:

- Don't inspect what gets written
- Don't verify integrity on read
- Treat embeddings as opaque numerical artifacts

That's a giant attack surface. The companion [VectorSmuggle](https://github.com/jaschadub/VectorSmuggle) research project demonstrates that an attacker with write access to a vector pipeline can hide arbitrary data inside embeddings using techniques that pass standard observability:

- Noise injection, rotation, scaling, and offset perturbations
- Cross-model fragmentation
- Steganographic encoding that survives database quantization

Cryptographic pinning is the kill shot for these attacks. Every steganographic technique requires modifying the vector after the model produces it. If each vector ships with a signed attestation binding it to its source text and the producing model, any modification made *after signing* to the stored vector — in the precision the store persists, down to a single bit — breaks verification. Two boundaries matter: the protected interval begins at signing (a writer upstream of the signer is not caught — see [Threat model](#threat-model)), and VectorPin verifies the stored vector in its native dtype, not quantized index copies (PQ codes, binary or half-precision index structures) built from it — see [Quantization boundary](docs/security.md#quantization-boundary). A verifier never narrows a wider stored vector before hashing: an f64 store checked against an f32 pin is refused outright, because the bits a cast discards would otherwise be an unverified covert channel.

## Quick start

### Python

```bash
pip install vectorpin
```

```python
import numpy as np
from vectorpin import Signer, Verifier

# At ingestion time
signer = Signer.generate(key_id="prod-2026-05")
embedding = my_model.embed("The quick brown fox.")
pin = signer.pin(
    source="The quick brown fox.",
    model="text-embedding-3-large",
    vector=embedding,
)
# Store pin.to_json() alongside the embedding in your vector DB metadata.

# At read/audit time
verifier = Verifier({"prod-2026-05": signer.public_key_bytes()})
result = verifier.verify(pin, source="The quick brown fox.", vector=embedding)
if not result.ok:
    print(f"INTEGRITY FAILURE: {result.error.value} — {result.detail}")
```

### Rust

```toml
[dependencies]
vectorpin = "0.1"
```

```rust
use vectorpin::{Signer, Verifier};

let signer = Signer::generate("prod-2026-05".to_string());
let embedding: Vec<f32> = my_model_embed("The quick brown fox.");
let pin = signer.pin(
    "The quick brown fox.",
    "text-embedding-3-large",
    embedding.as_slice(),
)?;

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

### TypeScript / JavaScript

```bash
npm install vectorpin
```

```ts
import { Signer, Verifier } from 'vectorpin';

const signer = Signer.generate('prod-2026-05');
const embedding = new Float32Array(/* ... 3072 floats from your model ... */);
const pin = signer.pin({
  source: 'The quick brown fox.',
  model: 'text-embedding-3-large',
  vector: embedding,
});

const verifier = new Verifier({ [signer.keyId]: signer.publicKeyBytes() });
const result = verifier.verify(pin, {
  source: 'The quick brown fox.',
  vector: embedding,
});
if (!result.ok) throw new Error(`integrity failure: ${result.error}`);
```

The Python, Rust, and TypeScript implementations are byte-for-byte compatible. A pin produced by any of them verifies on the other two, enforced by shared test vectors at [`testvectors/v2.json`](testvectors/) and [`testvectors/negative_v2.json`](testvectors/) consumed in all three test suites, each of which runs in CI (`ci.yml` has `python`, `rust`, and `typescript` jobs plus a job that regenerates the fixtures and runs every port's cross-language tests against them). The TS port is pure JavaScript via [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) with no dependency on Node's `Buffer`, so it also runs in Deno, Bun, and edge runtimes.

Pin under the dtype your store persists. Signers default to the input array's native dtype (`float32` → `f32`, `float64` → `f64`); verifiers refuse a stored vector wider than the pinned dtype and will not hash-match a narrower one. If your embedding API hands you 64-bit floats but your store persists 32-bit, pass `vec_dtype="f32"` (`vecDtype: 'f32'`) explicitly.

## What VectorPin guarantees

Each Pin commits to:

- **The source text**, by SHA-256 of UTF-8 NFC-normalized bytes.
- **The model**, by identifier (and optionally by content hash).
- **The vector itself**, by SHA-256 of canonical little-endian bytes.
- **The producer**, by Ed25519 signing key.
- **The time**, by RFC 3339 timestamp.

Verification distinguishes failure modes so callers can route them differently:

| Outcome | Meaning |
|---|---|
| `OK` | Signature valid, vector intact, source matches. |
| `SIGNATURE_INVALID` | Pin was forged or re-signed by an attacker. |
| `VECTOR_TAMPERED` | Embedding modified after pinning. **This is the steganography kill shot.** |
| `SOURCE_MISMATCH` | Source text differs from what was pinned. |
| `MODEL_MISMATCH` | Pin was produced by a different embedding model than expected. |
| `UNKNOWN_KEY` | Pin signed by a key not in the verifier's registry. |
| `SHAPE_MISMATCH` / `UNSUPPORTED_VERSION` | Structural problems with the data. |

## CLI

```bash
# Generate a signing key pair
vectorpin keygen --key-id prod-2026-05 --output ./keys

# Pin a single (text, vector) pair (debug/demo)
vectorpin pin \
    --private-key ./keys/prod-2026-05.priv \
    --key-id prod-2026-05 \
    --model text-embedding-3-large \
    --source ./doc.txt \
    --vector ./embedding.npy

# Verify a pin
vectorpin verify-pin \
    --public-key ./keys/prod-2026-05.pub \
    --key-id prod-2026-05 \
    --pin ./pin.json \
    --source ./doc.txt \
    --vector ./embedding.npy

# Audit an entire LanceDB table (recommended default backend)
vectorpin audit-lancedb \
    --uri ./data/vector_db \
    --table symbiont_context \
    --public-key ./keys/prod-2026-05.pub \
    --key-id prod-2026-05 \
    --source-column content    # Symbiont default; omit to skip source verification

# Audit a Chroma collection
vectorpin audit-chroma \
    --path ./chroma_db \
    --collection my-rag \
    --public-key ./keys/prod-2026-05.pub \
    --key-id prod-2026-05 \
    --source-metadata-key text

# Audit a Qdrant collection
vectorpin audit-qdrant \
    --url http://localhost:6333 \
    --collection my-rag \
    --public-key ./keys/prod-2026-05.pub \
    --key-id prod-2026-05
```

Audit commands print a JSON summary (`total`, `pinned`, `verified_ok`, `verification_failed`, `unpinned`) on stdout and exit non-zero on any verification failure, so they compose cleanly into CI or a cron job.

## Vector store integrations

| Backend | Status | Install |
|---|---|---|
| LanceDB *(default)* | Alpha | `pip install 'vectorpin[default]'` |
| Chroma | Alpha | `pip install 'vectorpin[chroma]'` |
| Pinecone | Alpha | `pip install 'vectorpin[pinecone]'` |
| Qdrant | Alpha | `pip install 'vectorpin[qdrant]'` |
| pgvector | Planned | — |
| FAISS | Planned | Use `LanceDBAdapter` (embedded, has metadata column natively). |

LanceDB is the recommended default: embedded, file-based, no daemon, with a typed schema column that holds the Pin natively — matching the [Symbiont runtime's](https://github.com/thirdkeyai/symbiont) default vector backend. Choose Chroma or Pinecone if you already run those; Qdrant if you need server-side payload filtering.

For Symbiont deployments, the source text the embedding was produced from lives in Symbiont's `content` column (Symbiont's column literally named `source` is upstream provenance like a URL, not VectorPin's `source` argument). Pass `source=record.metadata["content"]` when calling `signer.pin`. See `tests/test_adapter_lancedb_symbiont.py` for an end-to-end example against the Symbiont schema.

```python
from vectorpin import Signer, Verifier
from vectorpin.adapters import LanceDBAdapter

adapter = LanceDBAdapter.connect("./data/vector_db", "rag-corpus")
signer = Signer.generate(key_id="prod-2026-05")
verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})

# Replace "text" below with whichever column on your table holds
# the source text the embedding was produced from. On Symbiont's
# default schema, that column is named "content".
for record in adapter.iter_records():
    pin = signer.pin(
        source=record.metadata["text"],
        model="text-embedding-3-large",
        vector=record.vector,
    )
    adapter.attach_pin(record.id, pin)
```

The [adapter protocol](src/vectorpin/adapters/base.py) is intentionally thin; community contributions for new backends are welcome.

## Performance

Pinning and verification are sub-millisecond per vector on commodity hardware — well below the embedding-model latency they sit alongside. Microbenchmarks for both implementations live at [`rust/vectorpin/benches/perf.rs`](rust/vectorpin/benches/perf.rs) (criterion) and [`scripts/bench_python.py`](scripts/bench_python.py) (`time.perf_counter_ns`).

```bash
# Rust (criterion writes a report to target/criterion/)
cd rust && cargo bench --bench perf

# Python (standalone, no extra deps)
python scripts/bench_python.py --iters 5000
```

Indicative numbers on a modern x86_64 laptop, 3072-dim vectors (matching `text-embedding-3-large`):

| Operation | Rust (µs) | Python (µs) |
|---|---|---|
| `hash_vector` | 6.4 | 5.8 |
| `sign` (pin) | 35 | 35 |
| `verify_full` | 42 | 79 |
| `verify_signature_only` | 22 | 75 |

Re-run on your own hardware before quoting numbers.

## Statistical detectors

Pinning catches modifications. Detectors catch ingestion-time tampering and poisoning campaigns that inject new tampered vectors. The two are complementary defenses:

```python
from vectorpin.detectors.isolation_forest import IsolationForestDetector

detector = IsolationForestDetector().fit(clean_embeddings)
flagged = detector.decide(suspect_embeddings)
```

In the VectorSmuggle empirical study, this single line of defense flagged every operating point of every distribution-shifting steganographic technique that hides a non-trivial amount of data — but it does not catch orthogonal rotation (which preserves every density feature the detector fits on) and is brittle against attackers who know the detector. Cryptographic pinning is the durable layer; statistical detection is defense-in-depth.

## Threat model

**The protected interval begins at signing.** A pin proves that the vector has not changed since the signer saw it; it cannot prove anything about what happened before. VectorPin is designed against an attacker who, *after* a pin is signed, can:

- Modify vectors in the vector DB, in backups, or anywhere downstream of the signer — in the dtype the store persists (any magnitude, down to a single bit) or in a wider representation (refused outright, never narrowed)
- See the public verification key, but not the private signing key
- Replay pins across records, collections, or tenants (caught when `vectorpin.record_id` / `collection_id` / `tenant_id` are bound and enforced — the audit CLI enforces `record_id` by default)
- Strip or blank pins, or delete and insert records (caught by the fail-closed audit, which treats an unpinned record as a failure unless `--allow-unpinned`, and by a signed per-collection manifest — count plus Merkle root — produced at ingestion and checked with `--manifest`)

VectorPin does **not** defend against:

- An attacker with the private signing key, or with write access to the component that invokes it. A "poisoned ingestion pipeline" is in scope only downstream of the signer: if the attacker's write point is upstream of (or is) the signing call, the steganographic vector is signed legitimately. Move signing to the earliest trustworthy point — a separate signing service or KMS the pipeline cannot invoke arbitrarily, rate-limited and logged — rather than co-locating it with ingestion. See [Deployment](docs/deployment.md#architecture-overview).
- An attacker who modifies the source documents *before* embedding (use upstream content integrity controls)
- Model substitution by label: `model` is a self-declared string and `model_hash` is only as trustworthy as the signer that wrote it. Require a specific hash with `expected_model_hash` / `--expected-model-hash` where the weights are known; nothing fingerprints the producing model otherwise.
- Backdating against revocation: `ts` is signer-chosen, so a `valid_until` window on its own only bounds honest signers. Supply a verifier-trusted ingestion time (`trusted_time` / `trustedTime` / `VerifyOptions::trusted_time`) from a clock the key holder cannot write to close this. See [`docs/spec.md`](docs/spec.md) §7.

## Status

Beta (`v0.2`). Core protocol (`Pin`, `Signer`, `Verifier`) is stable and tested. The Python, Rust, and TypeScript ports are byte-for-byte compatible and locked together by shared test vectors in CI. Adapter coverage is partial. Hosted attestation service is not yet available.

The protocol version field (`v: 2`) lets future revisions break compatibility cleanly. We will not break existing pins without bumping the major version. See [`docs/spec.md`](docs/spec.md) for the wire-format specification.

## Citation

If you reference VectorPin or the threat model it defends against, please cite the companion preprint:

> Wanger, J. (2026). *VectorSmuggle: Steganographic Exfiltration in Embedding Stores and a Cryptographic Provenance Defense*. arXiv:2605.13764. <https://arxiv.org/abs/2605.13764> ([PDF](https://arxiv.org/pdf/2605.13764)) · Zenodo mirror: <https://doi.org/10.5281/zenodo.20058256>

```bibtex
@misc{wanger2026vectorsmuggle,
  title  = {{VectorSmuggle}: Steganographic Exfiltration in Embedding Stores and a Cryptographic Provenance Defense},
  author = {Wanger, Jascha},
  year   = {2026},
  eprint = {2605.13764},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  doi    = {10.5281/zenodo.20058256},
  url    = {https://arxiv.org/abs/2605.13764}
}
```

## Related work

- [VectorSmuggle](https://github.com/jaschadub/VectorSmuggle) — companion threat-research project demonstrating the attacks VectorPin defends against. Empirical results in the [arXiv preprint](https://arxiv.org/abs/2605.13764).
- [Symbiont](https://github.com/ThirdKeyAI/Symbiont) — policy-governed agent runtime. Its enterprise console backend consumes VectorPin attestations (an optional dependency on this crate) to enforce "agents may only retrieve from verified vector stores"; the open-source runtime does not yet integrate VectorPin.
- [SchemaPin](https://github.com/ThirdKeyAI/SchemaPin) — sister project doing the same kind of cryptographic provenance for tool schemas in MCP.
- [sigstore](https://www.sigstore.dev/) — inspired our approach to OSS-friendly cryptographic provenance.

## Contributing

Issues and PRs welcome. For security-sensitive findings, please email `security@thirdkey.ai` rather than filing public issues.

## License

Apache 2.0. See [LICENSE](LICENSE).
