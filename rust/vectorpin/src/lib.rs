// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Verifiable integrity for AI embedding stores.
//!
//! VectorPin pins each embedding to its source content and the model that
//! produced it via an Ed25519 signature over a canonical byte representation.
//! Any post-pinning modification of the vector or the source text breaks
//! signature verification — including covert
//! [steganographic exfiltration attacks](https://doi.org/10.5281/zenodo.20058256)
//! that current vector databases ingest without complaint.
//!
//! This crate is the **Rust reference implementation** of protocol version 2.
//! It is byte-for-byte compatible with the Python reference (`pip install
//! vectorpin`) and the TypeScript reference (`npm install vectorpin`); a pin
//! produced by any of the three implementations verifies on the other two.
//! v2 is a wire-format break with v1; pass through [`verifier::LegacyV1Verifier`]
//! when migrating historical pins.
//! Compatibility is enforced by shared test vectors in
//! [`testvectors/`](https://github.com/ThirdKeyAI/VectorPin/tree/main/testvectors)
//! consumed by every port's test suite.
//!
//! Part of the [ThirdKey](https://thirdkey.ai) Trust Stack, alongside
//! [Symbiont](https://github.com/ThirdKeyAI/Symbiont) (the Rust-native
//! agent runtime that consumes these attestations).
//!
//! # Quick start
//!
//! ```
//! use vectorpin::{Signer, Verifier};
//!
//! // Ingestion: produce an embedding, sign a pin for it.
//! let signer = Signer::generate("prod-2026-05".to_string());
//! let embedding: Vec<f32> = vec![0.1, 0.2, 0.3, /* ... */];
//! let pin = signer
//!     .pin("The quick brown fox.", "text-embedding-3-large", embedding.as_slice())
//!     .expect("sign pin");
//!
//! // Persist `pin.to_json()` alongside the embedding in your vector DB.
//! let stored: String = pin.to_json();
//!
//! // Read/audit: parse the stored JSON and verify against ground truth.
//! let parsed = vectorpin::Pin::from_json(&stored).expect("parse pin");
//! let mut verifier = Verifier::new();
//! verifier.add_key(signer.key_id(), signer.public_key_bytes());
//!
//! let result = verifier.verify_full(
//!     &parsed,
//!     Some("The quick brown fox."),
//!     Some(embedding.as_slice()),
//!     None,
//! );
//! assert!(result.is_ok());
//! # let _ = stored;
//! ```
//!
//! # What a Pin commits to
//!
//! Each [`Pin`] is a JSON object that binds:
//!
//! | Field | What it pins |
//! |---|---|
//! | `source_hash` | SHA-256 of the source text (UTF-8 NFC) |
//! | `vec_hash` | SHA-256 of the canonical little-endian vector bytes |
//! | `model` | embedding model identifier (and optionally `model_hash`) |
//! | `vec_dtype`, `vec_dim` | byte-format reproducibility |
//! | `ts` | RFC 3339 timestamp |
//! | `kid` | signing-key identifier (for rotation) |
//! | `sig` | Ed25519 signature over the canonical header bytes |
//!
//! Producer-defined string-to-string metadata can be supplied via
//! [`signer::PinOptions::extra`]; it is signed alongside the rest of the
//! header.
//!
//! # Failure modes
//!
//! [`Verifier::verify_full`] distinguishes failure modes via [`VerifyError`]
//! so callers can route them differently:
//!
//! | Variant | Meaning |
//! |---|---|
//! | [`VerifyError::SignatureInvalid`] | Pin was forged or re-signed by an attacker |
//! | [`VerifyError::VectorTampered`] | Embedding modified after pinning — the steganography kill shot |
//! | [`VerifyError::SourceMismatch`] | Source text differs from what was pinned |
//! | [`VerifyError::ModelMismatch`] | Pin produced by a different embedding model than expected |
//! | [`VerifyError::UnknownKey`] | Pin signed by a key not in the verifier's registry |
//! | [`VerifyError::UnsupportedVersion`] | Protocol version mismatch |
//! | [`VerifyError::ShapeMismatch`] | Supplied vector's dim disagrees with the pin header |
//!
//! # Architecture
//!
//! The crate has four modules, each owning one piece of the protocol:
//!
//! | Module | Role |
//! |---|---|
//! | [`hash`] | Canonical hashing of vectors and source text — the *only* place where bytes meet semantics. |
//! | [`attestation`] | [`Pin`] / [`PinHeader`] data structures and canonical JSON serialization. |
//! | [`signer`] | [`Signer`] — wraps an Ed25519 signing key, produces pins. |
//! | [`verifier`] | [`Verifier`] — holds a key registry and validates pins against ground truth. |
//!
//! For the wire-format specification (every byte of canonicalization,
//! every protocol field, every supported failure mode), see
//! [`docs/spec.md`](https://github.com/ThirdKeyAI/VectorPin/blob/main/docs/spec.md).
//!
//! # Threat model
//!
//! VectorPin is designed against an attacker who can:
//!
//! * Modify vectors after they are produced — via a poisoned ingestion
//!   pipeline, a compromised vector DB, or backup-level access.
//! * See the public verification key but not the private signing key.
//! * Replay or selectively delete pins.
//!
//! VectorPin does **not** defend against:
//!
//! * An attacker with the private signing key (out of scope; key custody
//!   is the user's responsibility).
//! * An attacker who modifies the source documents *before* embedding
//!   (use upstream content integrity controls).
//! * An attacker who uses a legitimate signing key to attest a malicious
//!   vector at ingestion time (use upstream input validation).
//!
//! For the empirical evaluation of the attack class VectorPin is built to
//! defeat, see the companion preprint at
//! [10.5281/zenodo.20058256](https://doi.org/10.5281/zenodo.20058256).

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(rustdoc::broken_intra_doc_links)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod attestation;
pub mod hash;
pub mod signer;
pub mod verifier;

pub use attestation::{AttestationError, Pin, PinHeader, DOMAIN_TAG, PROTOCOL_VERSION};
pub use hash::{canonical_vector_bytes, hash_text, hash_vector, VecDtype};
pub use signer::{Signer, SignerError};
pub use verifier::{KeyEntry, LegacyV1Verifier, Verifier, VerifyError, VerifyOptions};
