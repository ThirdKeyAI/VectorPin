# vectorpin

[![Crates.io](https://img.shields.io/crates/v/vectorpin.svg)](https://crates.io/crates/vectorpin)
[![Docs.rs](https://docs.rs/vectorpin/badge.svg)](https://docs.rs/vectorpin)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Verifiable integrity for AI embedding stores. Rust reference implementation of the [VectorPin](https://github.com/ThirdKeyAI/VectorPin) attestation protocol.

VectorPin pins each embedding to its source content and the producing model via an Ed25519 signature over a canonical byte representation. Any post-pinning modification of the vector or source text — including covert [steganographic exfiltration attacks](https://doi.org/10.5281/zenodo.20058256) that current vector databases ingest without complaint — breaks signature verification on read.

This crate is **byte-for-byte compatible** with the Python reference (`pip install vectorpin`) and the TypeScript reference (`npm install vectorpin`). A pin produced by any of the three implementations verifies on the other two; the contract is enforced by shared test vectors that every port consumes in CI.

Part of the [ThirdKey](https://thirdkey.ai) Trust Stack, alongside [Symbiont](https://github.com/ThirdKeyAI/Symbiont) — the Rust-native policy-governed agent runtime. Symbiont's enterprise console backend consumes these attestations in-process (an optional dependency on this crate); the open-source runtime does not yet integrate VectorPin.

Vectors are verified in their native precision: an `f64` slice against an `f32` pin is refused (`VerifyError::PrecisionWidening`) rather than narrowed, so pin under the dtype your store persists (`Signer::pin` defaults to the input slice's dtype).

## Quick start

```toml
[dependencies]
vectorpin = "0.1"
```

```rust
use vectorpin::{Signer, Verifier};

// Ingestion: produce an embedding, sign a pin for it.
let signer = Signer::generate("prod-2026-05".to_string());
let embedding: Vec<f32> = my_model_embed("The quick brown fox.");

let pin = signer.pin(
    "The quick brown fox.",
    "text-embedding-3-large",
    embedding.as_slice(),
)?;

// Persist `pin.to_json()` alongside the embedding in your vector DB.
let stored: String = pin.to_json();

// Read/audit: parse the stored JSON and verify against ground truth.
let parsed = vectorpin::Pin::from_json(&stored)?;
let mut verifier = Verifier::new();
verifier.add_key(signer.key_id(), signer.public_key_bytes());

let result = verifier.verify_full(
    &parsed,
    Some("The quick brown fox."),
    Some(embedding.as_slice()),
    None,
);
assert!(result.is_ok());
```

## What gets pinned

Each `Pin` commits to:

- **The source text**, by SHA-256 of UTF-8 NFC-normalized bytes.
- **The model**, by identifier (and optionally by content hash).
- **The vector itself**, by SHA-256 of canonical little-endian f32/f64 bytes.
- **The producer**, by Ed25519 signing-key identifier (`kid`).
- **The time**, by RFC 3339 timestamp.

Verification distinguishes failure modes via the `VerifyError` enum so callers can route them differently:

| Variant | Meaning |
|---|---|
| `SignatureInvalid` | Pin was forged or re-signed by an attacker |
| `VectorTampered` | Embedding modified after pinning — the steganography kill shot |
| `SourceMismatch` | Source text differs from what was pinned |
| `ModelMismatch` | Pin produced by a different embedding model than expected |
| `UnknownKey` | Pin signed by a key not in the verifier's registry |
| `UnsupportedVersion` | Protocol version mismatch |
| `ShapeMismatch` | Supplied vector's dim disagrees with the pin header |

## Threat model

VectorPin is designed against an attacker who can:

- Modify vectors after they are produced — via a poisoned ingestion pipeline, a compromised vector DB, or backup-level access.
- See the public verification key but not the private signing key.
- Replay or selectively delete pins.

It does **not** defend against:

- An attacker with the private signing key (key custody is the user's responsibility).
- An attacker who modifies the source documents *before* embedding (use upstream content integrity controls).
- An attacker who uses a legitimate signing key to attest a malicious vector at ingestion time (use upstream input validation).

For the empirical evaluation of the attack class VectorPin is built to defeat, see the companion preprint at <https://doi.org/10.5281/zenodo.20058256>.

## Status

Alpha (`v0.1`). Protocol v1 stable; covered by the cross-language test vectors. The wire format will not break compatibility without a major-version bump.

See the full [protocol specification](https://github.com/ThirdKeyAI/VectorPin/blob/main/docs/spec.md) and [docs.rs](https://docs.rs/vectorpin) for the complete API reference.

## License

Apache 2.0.
