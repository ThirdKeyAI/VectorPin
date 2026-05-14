// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Pin verification.
//!
//! Mirrors the Python and TypeScript verifiers: same failure-mode
//! enum, same matching semantics, same support for partial verification
//! (signature-only, signature + vector, full).
//!
//! [`Verifier`] holds a registry of `kid -> public key` so it can verify
//! pins signed under multiple key ids during rotation. Add keys with
//! [`Verifier::add_key`] before calling [`Verifier::verify_full`] or
//! [`Verifier::verify_signature`]; missing-key errors surface as
//! [`VerifyError::UnknownKey`].
//!
//! # Examples
//!
//! Full verification — signature, vector hash, source hash:
//!
//! ```
//! use vectorpin::{Signer, Verifier};
//!
//! let signer = Signer::generate("k1".to_string()).unwrap();
//! let v: Vec<f32> = vec![1.0, 2.0, 3.0];
//! let pin = signer.pin("hello", "m", v.as_slice()).unwrap();
//!
//! let mut verifier = Verifier::new();
//! verifier.add_key(signer.key_id(), signer.public_key_bytes()).unwrap();
//! verifier
//!     .verify_full(&pin, Some("hello"), Some(v.as_slice()), None)
//!     .expect("honest verify must pass");
//! ```
//!
//! Signature-only verification (when ground-truth source/vector are not
//! on hand but producer identity still matters):
//!
//! ```
//! # use vectorpin::{Signer, Verifier};
//! # let signer = Signer::generate("k1".to_string()).unwrap();
//! # let v: Vec<f32> = vec![1.0, 2.0, 3.0];
//! # let pin = signer.pin("hello", "m", v.as_slice()).unwrap();
//! # let mut verifier = Verifier::new();
//! # verifier.add_key(signer.key_id(), signer.public_key_bytes()).unwrap();
//! verifier.verify_signature(&pin).unwrap();
//! ```
//!
//! Tampered vector — caught by [`VerifyError::VectorTampered`]:
//!
//! ```
//! # use vectorpin::{Signer, Verifier, VerifyError};
//! # let signer = Signer::generate("k1".to_string()).unwrap();
//! # let v: Vec<f32> = vec![1.0, 2.0, 3.0];
//! # let pin = signer.pin("hello", "m", v.as_slice()).unwrap();
//! # let mut verifier = Verifier::new();
//! # verifier.add_key(signer.key_id(), signer.public_key_bytes()).unwrap();
//! let mut tampered = v.clone();
//! tampered[0] += 1e-5;
//! let err = verifier
//!     .verify_full(&pin, None::<&str>, Some(tampered.as_slice()), None)
//!     .unwrap_err();
//! assert_eq!(err, VerifyError::VectorTampered);
//! ```
//!
//! Key rotation — accept both old and new `kid` during the rollover
//! window:
//!
//! ```
//! use vectorpin::{Signer, Verifier};
//!
//! let old = Signer::generate("2026-04".to_string()).unwrap();
//! let new = Signer::generate("2026-05".to_string()).unwrap();
//! let mut verifier = Verifier::new();
//! verifier.add_key(old.key_id(), old.public_key_bytes()).unwrap();
//! verifier.add_key(new.key_id(), new.public_key_bytes()).unwrap();
//!
//! let v: Vec<f32> = vec![1.0, 2.0];
//! let pin_old = old.pin("hello", "m", v.as_slice()).unwrap();
//! let pin_new = new.pin("hello", "m", v.as_slice()).unwrap();
//! verifier.verify_signature(&pin_old).unwrap();
//! verifier.verify_signature(&pin_new).unwrap();
//! ```

use std::collections::HashMap;

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

use crate::attestation::{Pin, PROTOCOL_VERSION};
use crate::hash::{hash_text, hash_vector, VecDtype, VectorRef};

/// Distinct verification failure modes. Callers route on this so a
/// signature-invalid result (potential forgery) can be handled
/// differently from a vector-tampered result (potential steganography
/// kill shot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Pin uses a protocol version this verifier does not understand.
    UnsupportedVersion(u32),
    /// `kid` not present in the verifier's key registry.
    UnknownKey(String),
    /// Ed25519 signature did not verify against the canonical header.
    SignatureInvalid,
    /// Vector hash mismatch — the embedding has been modified after pinning.
    VectorTampered,
    /// Source text hash mismatch.
    SourceMismatch,
    /// Pin was issued for a different model than the caller expected.
    ModelMismatch {
        /// Model identifier in the pin.
        pin_model: String,
        /// Model identifier the caller asked us to require.
        expected: String,
    },
    /// Supplied vector's dim did not match the dim in the pin header.
    ShapeMismatch {
        /// Length of the supplied vector.
        supplied: usize,
        /// `vec_dim` from the pin header.
        expected: u32,
    },
    /// Pin failed to parse one of its dtype-related fields.
    UnsupportedDtype(String),
    /// A public key handed to [`Verifier::add_key`] could not be decoded
    /// as a valid Ed25519 verifying key.
    KeyDecodeFailed(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::UnsupportedVersion(v) => write!(f, "unsupported pin version: {v}"),
            VerifyError::UnknownKey(k) => write!(f, "unknown signing key id: {k}"),
            VerifyError::SignatureInvalid => write!(f, "ed25519 signature did not verify"),
            VerifyError::VectorTampered => write!(
                f,
                "vector hash mismatch — embedding has been modified after pinning"
            ),
            VerifyError::SourceMismatch => write!(f, "source hash mismatch"),
            VerifyError::ModelMismatch {
                pin_model,
                expected,
            } => {
                write!(f, "pin model {pin_model:?} != expected {expected:?}")
            }
            VerifyError::ShapeMismatch { supplied, expected } => {
                write!(
                    f,
                    "vector shape mismatch: supplied len {supplied}, pin dim {expected}"
                )
            }
            VerifyError::UnsupportedDtype(s) => write!(f, "unsupported canonical dtype: {s}"),
            VerifyError::KeyDecodeFailed(reason) => {
                write!(f, "failed to decode ed25519 public key: {reason}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Holds the public-key registry for one or more `kid` values and runs
/// pin verification against supplied ground truth.
#[derive(Default)]
pub struct Verifier {
    keys: HashMap<String, VerifyingKey>,
}

impl Verifier {
    /// Construct an empty verifier. Add public keys with [`Self::add_key`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a public key under `kid`. Multiple keys may live in
    /// the registry simultaneously to support rotation.
    ///
    /// Returns [`VerifyError::KeyDecodeFailed`] if the supplied bytes
    /// are not a valid Ed25519 public key encoding (previously such
    /// keys were silently dropped).
    pub fn add_key(&mut self, kid: &str, public_key_bytes: [u8; 32]) -> Result<(), VerifyError> {
        let vk = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| VerifyError::KeyDecodeFailed(e.to_string()))?;
        self.keys.insert(kid.to_owned(), vk);
        Ok(())
    }

    /// Number of registered keys (sanity check for tests).
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Verify just the signature — useful when ground-truth source/vector
    /// are unavailable but producer identity still matters.
    pub fn verify_signature(&self, pin: &Pin) -> Result<(), VerifyError> {
        if pin.header.v != PROTOCOL_VERSION {
            return Err(VerifyError::UnsupportedVersion(pin.header.v));
        }
        let key = self
            .keys
            .get(&pin.kid)
            .ok_or_else(|| VerifyError::UnknownKey(pin.kid.clone()))?;
        let sig_bytes: [u8; 64] = pin
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::SignatureInvalid)?;
        let signature = Signature::from_bytes(&sig_bytes);
        key.verify(&pin.header.canonicalize(), &signature)
            .map_err(|_| VerifyError::SignatureInvalid)
    }

    /// Verify signature + any supplied ground truth.
    ///
    /// Pass `Some(...)` for whichever components you have on hand:
    /// the signature is always checked; source/vector/model checks run
    /// only when the corresponding argument is present. This mirrors
    /// the Python reference verifier so callers can do partial
    /// verification (e.g. signature-only at retrieval time, full
    /// verification at audit time).
    pub fn verify_full<'a, V>(
        &self,
        pin: &Pin,
        source: Option<&str>,
        vector: Option<V>,
        expected_model: Option<&str>,
    ) -> Result<(), VerifyError>
    where
        V: Into<VectorRef<'a>>,
    {
        self.verify_signature(pin)?;

        if let Some(vec) = vector {
            let vec = vec.into();
            let len_matches = u32::try_from(vec.len())
                .map(|n| n == pin.header.vec_dim)
                .unwrap_or(false);
            if !len_matches {
                return Err(VerifyError::ShapeMismatch {
                    supplied: vec.len(),
                    expected: pin.header.vec_dim,
                });
            }
            let dtype = VecDtype::parse(&pin.header.vec_dtype)
                .map_err(|_| VerifyError::UnsupportedDtype(pin.header.vec_dtype.clone()))?;
            if hash_vector(vec, dtype) != pin.header.vec_hash {
                return Err(VerifyError::VectorTampered);
            }
        }

        if let Some(s) = source {
            if hash_text(s) != pin.header.source_hash {
                return Err(VerifyError::SourceMismatch);
            }
        }

        if let Some(em) = expected_model {
            if pin.header.model != em {
                return Err(VerifyError::ModelMismatch {
                    pin_model: pin.header.model.clone(),
                    expected: em.to_owned(),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Signer;

    fn fixture(kid: &str) -> (Signer, Verifier, Vec<f32>) {
        let signer = Signer::generate(kid.into()).unwrap();
        let mut verifier = Verifier::new();
        verifier
            .add_key(signer.key_id(), signer.public_key_bytes())
            .unwrap();
        let v: Vec<f32> = (0..16).map(|i| (i as f32) * 0.1).collect();
        (signer, verifier, v)
    }

    #[test]
    fn verify_full_passes_on_honest_inputs() {
        let (signer, verifier, v) = fixture("k1");
        let pin = signer.pin("hello", "m", v.as_slice()).unwrap();
        verifier
            .verify_full(&pin, Some("hello"), Some(v.as_slice()), None)
            .expect("honest verify must succeed");
    }

    #[test]
    fn verify_signature_only_passes() {
        let (signer, verifier, v) = fixture("k1");
        let pin = signer.pin("hello", "m", v.as_slice()).unwrap();
        verifier.verify_signature(&pin).unwrap();
    }

    #[test]
    fn vector_tamper_is_caught() {
        let (signer, verifier, v) = fixture("k1");
        let pin = signer.pin("hello", "m", v.as_slice()).unwrap();
        let mut tampered = v.clone();
        tampered[0] += 1e-5;
        let err = verifier
            .verify_full(&pin, None::<&str>, Some(tampered.as_slice()), None)
            .unwrap_err();
        assert_eq!(err, VerifyError::VectorTampered);
    }

    #[test]
    fn source_mismatch_is_caught() {
        let (signer, verifier, v) = fixture("k1");
        let pin = signer.pin("hello", "m", v.as_slice()).unwrap();
        let err = verifier
            .verify_full(&pin, Some("HELLO"), None::<&[f32]>, None)
            .unwrap_err();
        assert_eq!(err, VerifyError::SourceMismatch);
    }

    #[test]
    fn unknown_key_is_caught() {
        let signer = Signer::generate("rogue".into()).unwrap();
        let v: Vec<f32> = vec![1.0, 2.0, 3.0];
        let pin = signer.pin("x", "m", v.as_slice()).unwrap();
        let other = Signer::generate("prod".into()).unwrap();
        let mut verifier = Verifier::new();
        verifier
            .add_key(other.key_id(), other.public_key_bytes())
            .unwrap();
        let err = verifier.verify_signature(&pin).unwrap_err();
        assert!(matches!(err, VerifyError::UnknownKey(_)));
    }

    #[test]
    fn shape_mismatch_is_caught() {
        let (signer, verifier, v) = fixture("k1");
        let pin = signer.pin("x", "m", v.as_slice()).unwrap();
        let truncated: Vec<f32> = v.iter().take(8).copied().collect();
        let err = verifier
            .verify_full(&pin, None::<&str>, Some(truncated.as_slice()), None)
            .unwrap_err();
        assert!(matches!(err, VerifyError::ShapeMismatch { .. }));
    }

    #[test]
    fn model_mismatch_is_caught() {
        let (signer, verifier, v) = fixture("k1");
        let pin = signer.pin("x", "model-A", v.as_slice()).unwrap();
        let err = verifier
            .verify_full(&pin, None::<&str>, None::<&[f32]>, Some("model-B"))
            .unwrap_err();
        assert!(matches!(err, VerifyError::ModelMismatch { .. }));
    }

    #[test]
    fn key_rotation_works() {
        let old = Signer::generate("2026-04".into()).unwrap();
        let new = Signer::generate("2026-05".into()).unwrap();
        let mut verifier = Verifier::new();
        verifier
            .add_key(old.key_id(), old.public_key_bytes())
            .unwrap();
        verifier
            .add_key(new.key_id(), new.public_key_bytes())
            .unwrap();
        let v: Vec<f32> = vec![1.0, 2.0];
        verifier
            .verify_signature(&old.pin("x", "m", v.as_slice()).unwrap())
            .unwrap();
        verifier
            .verify_signature(&new.pin("x", "m", v.as_slice()).unwrap())
            .unwrap();
    }
}
