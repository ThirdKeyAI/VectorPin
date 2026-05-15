# VectorPin

**Verifiable integrity for AI embedding stores.**

VectorPin is the provenance layer of the [ThirdKey](https://thirdkey.ai) trust stack: [SchemaPin](https://schemapin.org) (tool integrity) → [AgentPin](https://agentpin.org) (agent identity) → **VectorPin** (vector store integrity) → [Symbiont](https://symbiont.dev) (runtime).

---

## What VectorPin Does

Vector databases sit underneath every modern RAG system, but most are written and read with zero integrity checking. VectorPin binds each embedding to its source content and the model that produced it, then verifies that nothing has changed — including covert steganographic modifications invisible to traditional DLP.

- **Pinning** — Sign a compact attestation that commits to the source text (SHA-256 of NFC-normalized UTF-8), the model identifier, the vector itself (SHA-256 of canonical little-endian bytes), the producer (Ed25519 key), and an RFC 3339 timestamp.
- **Verification** — Reject any embedding whose hash, source, model, signature, or `kid` does not match. Distinguish `VECTOR_TAMPERED` from `SOURCE_MISMATCH` from `UNKNOWN_KEY` so callers can route them.
- **Auditing** — Walk a whole LanceDB / Chroma / Qdrant / Pinecone collection and report on every record. JSON summary on stdout, non-zero exit on any failure — drops into CI or cron unchanged.
- **Key rotation** — Verifier registries hold multiple `kid → public_key` mappings, each with a `(valid_from, valid_until)` window. Old pins keep verifying; compromised keys produce `KEY_EXPIRED` for anything signed after the compromise instant.
- **Cross-language** — Python, Rust, and TypeScript implementations are byte-for-byte compatible, locked by shared test vectors in CI.

## Quick Example

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

## Implementations

| Language | Package | Install |
|----------|---------|---------|
| **Python** | `vectorpin` | `pip install vectorpin` |
| **Rust** | `vectorpin` | `cargo add vectorpin` |
| **TypeScript** | `vectorpin` | `npm install vectorpin` |

All three are byte-for-byte compatible — a pin produced by any implementation verifies on the other two. The TS port is pure JavaScript via `@noble/ed25519` and `@noble/hashes`, so it also runs in Deno, Bun, and edge runtimes.

## Why this matters

Modern RAG systems convert sensitive content into high-dimensional vectors and store them in databases that don't inspect what gets written, don't verify integrity on read, and treat embeddings as opaque numerical artifacts. That's a giant attack surface.

The companion [VectorSmuggle](https://github.com/jaschadub/VectorSmuggle) research project demonstrates that an attacker with write access to a vector pipeline can hide arbitrary data inside embeddings using noise injection, rotation, scaling, offset perturbations, cross-model fragmentation, and steganographic encoding that survives quantization.

Cryptographic pinning is the kill shot. Every steganographic technique requires modifying the vector after the model produces it. If each vector ships with a signed attestation binding it to source text and producing model, any modification breaks the signature.

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](getting-started.md) | Install, generate keys, pin and verify embeddings |
| [Pin Protocol](pin-protocol.md) | Wire format, canonicalization, and verification order |
| [CLI Guide](cli-guide.md) | `vectorpin keygen`, `pin`, `verify-pin`, and `audit-*` commands |
| [Vector Store Adapters](adapters.md) | LanceDB, Chroma, Qdrant, Pinecone integrations |
| [Statistical Detectors](detectors.md) | Defense-in-depth against ingestion-time poisoning |
| [Deployment](deployment.md) | Key custody, rotation, and CI integration |
| [Security](security.md) | Threat model and best practices |
| [Troubleshooting](troubleshooting.md) | Common errors and solutions |
| [Specification](spec.md) | Protocol v2 wire-format specification |

## Links

- [GitHub](https://github.com/ThirdKeyAI/VectorPin)
- [VectorSmuggle preprint](https://doi.org/10.5281/zenodo.20058256)
- [Symbiont runtime](https://github.com/ThirdKeyAI/Symbiont)
- [ThirdKey](https://thirdkey.ai)
