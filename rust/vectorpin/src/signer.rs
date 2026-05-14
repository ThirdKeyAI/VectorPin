// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Pin signing.
//!
//! Wraps an Ed25519 signing key plus a `kid` (key id) so verifiers can
//! route signatures during key rotation. Use [`Signer::generate`] for
//! tests and demos; load production keys from a managed secret store
//! via [`Signer::from_private_bytes`].
//!
//! # Examples
//!
//! ```
//! use vectorpin::Signer;
//!
//! let signer = Signer::generate("prod-2026-05".to_string()).unwrap();
//! let v: Vec<f32> = vec![0.1, 0.2, 0.3];
//! let pin = signer.pin("hello", "text-embedding-3-large", v.as_slice()).unwrap();
//! assert_eq!(pin.kid, "prod-2026-05");
//! assert_eq!(pin.sig.len(), 64); // Ed25519 signature
//! ```
//!
//! For deterministic signing (test fixtures, reproducible CI builds),
//! use [`PinOptions`] to supply an explicit timestamp and dtype:
//!
//! ```
//! use vectorpin::signer::{PinOptions, Signer};
//! use vectorpin::VecDtype;
//!
//! let signer = Signer::generate("test".to_string()).unwrap();
//! let v: Vec<f32> = vec![0.1, 0.2, 0.3];
//! let opts = PinOptions {
//!     dtype: Some(VecDtype::F32),
//!     timestamp: Some("2026-05-05T12:00:00Z".to_string()),
//!     ..PinOptions::default()
//! };
//! let pin = signer
//!     .pin_with_options("hello", "test-model", v.as_slice(), opts)
//!     .unwrap();
//! assert_eq!(pin.header.ts, "2026-05-05T12:00:00Z");
//! ```

use std::collections::BTreeMap;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::attestation::{Pin, PinHeader, PROTOCOL_VERSION};
use crate::hash::{hash_text, hash_vector, VecDtype, VectorRef};

/// Errors raised by signer construction or pinning.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// `key_id` was empty.
    #[error("key_id must be non-empty")]
    EmptyKeyId,
    /// Private key bytes were the wrong length (must be 32).
    #[error("private key must be exactly 32 bytes, got {0}")]
    BadKeyLength(usize),
    /// Vector was empty or otherwise unrepresentable.
    #[error("invalid vector: {0}")]
    InvalidVector(&'static str),
}

/// Produces signed [`Pin`] attestations.
///
/// A `Signer` holds one Ed25519 private key plus a stable identifier
/// (`kid`) that gets embedded in every pin it produces. Verifiers use
/// the `kid` to look up the matching public key in their registry, so
/// rotating signing keys is a matter of issuing a new `(kid, key)` pair
/// and accepting both the old and new `kid` values during the rotation
/// window — no protocol changes required.
///
/// # Secret material
///
/// [`Signer::generate`] is for tests, demos, and one-off CLI tools.
/// In production, hold the 32-byte private seed in a managed secrets
/// store (HSM, KMS, sealed env var) and instantiate via
/// [`Signer::from_private_bytes`]. [`Signer::private_key_bytes`] is
/// provided for backup/key-export workflows; treat its output as
/// secret.
pub struct Signer {
    signing_key: SigningKey,
    key_id: String,
}

impl Signer {
    /// Generate a fresh Ed25519 signer. Tests and demos only.
    ///
    /// Returns [`SignerError::EmptyKeyId`] if `key_id` is empty so the
    /// constructor matches the contract of [`Signer::from_private_bytes`].
    pub fn generate(key_id: String) -> Result<Self, SignerError> {
        if key_id.is_empty() {
            return Err(SignerError::EmptyKeyId);
        }
        let mut rng = rand::rngs::OsRng;
        Ok(Signer {
            signing_key: SigningKey::generate(&mut rng),
            key_id,
        })
    }

    /// Load a signer from a 32-byte raw Ed25519 private seed.
    pub fn from_private_bytes(raw: &[u8], key_id: String) -> Result<Self, SignerError> {
        if key_id.is_empty() {
            return Err(SignerError::EmptyKeyId);
        }
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| SignerError::BadKeyLength(raw.len()))?;
        Ok(Signer {
            signing_key: SigningKey::from_bytes(&bytes),
            key_id,
        })
    }

    /// Identifier of the key used to sign — published in produced pins as `kid`.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// 32-byte raw Ed25519 public key. This is what verifiers register.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        VerifyingKey::from(&self.signing_key).to_bytes()
    }

    /// 32-byte raw Ed25519 private seed, wrapped in [`Zeroizing`] so the
    /// buffer is wiped from memory on drop. Treat the contents as
    /// secret; deref the returned value to access the raw `[u8; 32]`.
    pub fn private_key_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// Create a [`Pin`] for `(source, model, vector)`.
    ///
    /// `vector` accepts anything that converts into a [`VectorRef`],
    /// which includes `&[f32]` and `&[f64]`. The dtype written into
    /// the header defaults to the native dtype of the slice.
    pub fn pin<'a>(
        &self,
        source: &str,
        model: &str,
        vector: impl Into<VectorRef<'a>>,
    ) -> Result<Pin, SignerError> {
        self.pin_with_options(source, model, vector, PinOptions::default())
    }

    /// [`Self::pin`] with explicit dtype, model hash, timestamp, and
    /// `extra` map. Used by deterministic test-vector generation.
    pub fn pin_with_options<'a>(
        &self,
        source: &str,
        model: &str,
        vector: impl Into<VectorRef<'a>>,
        opts: PinOptions,
    ) -> Result<Pin, SignerError> {
        let vector = vector.into();
        if vector.is_empty() {
            return Err(SignerError::InvalidVector("empty vector"));
        }

        let dtype = opts.dtype.unwrap_or_else(|| vector.native_dtype());
        let ts = opts.timestamp.unwrap_or_else(now_utc_iso8601);

        let vec_dim = u32::try_from(vector.len())
            .map_err(|_| SignerError::InvalidVector("vec_dim exceeds u32"))?;

        let header = PinHeader {
            v: PROTOCOL_VERSION,
            model: model.to_owned(),
            model_hash: opts.model_hash,
            source_hash: hash_text(source),
            vec_hash: hash_vector(vector, dtype),
            vec_dtype: dtype.as_str().to_owned(),
            vec_dim,
            ts,
            extra: opts.extra,
        };

        let signature = self.signing_key.sign(&header.canonicalize());
        Ok(Pin {
            header,
            kid: self.key_id.clone(),
            sig: signature.to_bytes().to_vec(),
        })
    }
}

/// Optional knobs for [`Signer::pin_with_options`].
///
/// Defaults match what `Signer::pin` uses: native dtype, no model hash,
/// current UTC time, no extra metadata.
#[derive(Debug, Default, Clone)]
pub struct PinOptions {
    /// Override the canonical dtype the vector is hashed under.
    pub dtype: Option<VecDtype>,
    /// Optional content hash of the model weights.
    pub model_hash: Option<String>,
    /// Optional explicit timestamp string (must already be in
    /// `YYYY-MM-DDTHH:MM:SSZ` form).
    pub timestamp: Option<String>,
    /// Optional string-to-string `extra` map. Values are signed.
    pub extra: BTreeMap<String, String>,
}

fn now_utc_iso8601() -> String {
    // Produce a second-resolution UTC timestamp in `YYYY-MM-DDTHH:MM:SSZ`
    // form, matching the existing wire-format contract. The v1.1 branch
    // is responsible for any tightening of this format.
    let now = time::OffsetDateTime::now_utc();
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
    );
    now.format(&fmt)
        .expect("UTC OffsetDateTime always formats with a fixed description")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_round_trip_basic() {
        let signer = Signer::generate("test".into()).unwrap();
        let v: Vec<f32> = vec![1.0, 2.0, 3.0];
        let pin = signer.pin("hello", "model", v.as_slice()).unwrap();
        assert_eq!(pin.kid, "test");
        assert_eq!(pin.header.vec_dim, 3);
        assert_eq!(pin.header.vec_dtype, "f32");
        assert_eq!(pin.sig.len(), 64);
    }

    #[test]
    fn generate_rejects_empty_kid() {
        let res = Signer::generate("".into());
        assert!(matches!(res, Err(SignerError::EmptyKeyId)));
    }

    #[test]
    fn from_private_bytes_rejects_empty_kid() {
        let res = Signer::from_private_bytes(&[0u8; 32], "".into());
        assert!(matches!(res, Err(SignerError::EmptyKeyId)));
    }

    #[test]
    fn from_private_bytes_rejects_bad_length() {
        let res = Signer::from_private_bytes(&[0u8; 16], "k".into());
        assert!(matches!(res, Err(SignerError::BadKeyLength(16))));
    }

    #[test]
    fn private_seed_round_trip() {
        let signer = Signer::generate("k".into()).unwrap();
        let seed = signer.private_key_bytes();
        let restored = Signer::from_private_bytes(seed.as_ref(), "k".into()).unwrap();
        assert_eq!(signer.public_key_bytes(), restored.public_key_bytes());
    }
}
