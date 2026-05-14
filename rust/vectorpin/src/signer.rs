// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Pin signing (protocol v2).
//!
//! Wraps an Ed25519 signing key plus a `kid` (key id) that is bound into
//! every pin's canonical bytes. Use [`Signer::generate`] for tests and
//! demos; load production keys via [`Signer::from_private_bytes`] from a
//! managed secret store.
//!
//! v2 sign-time rules (mirroring [`docs/spec.md`](https://github.com/ThirdKeyAI/VectorPin/blob/main/docs/spec.md)):
//!
//! - All string inputs are NFC-normalized before signing.
//! - Control characters (U+0000..U+001F) and bidi overrides
//!   (U+202A..U+202E, U+2066..U+2069) are rejected.
//! - Vectors containing NaN/Inf are rejected — `-0.0` and `+0.0` are
//!   distinct values and both valid.
//! - `ts` is always written in the strict `YYYY-MM-DDTHH:MM:SSZ` form.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use unicode_normalization::UnicodeNormalization;

use crate::attestation::{
    check_nfc, check_string_safe, AttestationError, Pin, PinHeader, PROTOCOL_VERSION,
};
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
    /// Vector was empty, malformed, or contained NaN/Inf.
    #[error("invalid vector: {0}")]
    InvalidVector(String),
    /// A caller-supplied string violated v2 wire-format rules.
    #[error("invalid string input: {0}")]
    InvalidString(#[from] AttestationError),
}

/// Produces signed [`Pin`] attestations.
pub struct Signer {
    signing_key: SigningKey,
    key_id: String,
}

impl Signer {
    /// Generate a fresh Ed25519 signer. Tests and demos only.
    ///
    /// Panics if `key_id` is empty (the API for new pins requires a kid
    /// — tests are the only generation path and a panic is acceptable
    /// there).
    pub fn generate(key_id: String) -> Self {
        assert!(!key_id.is_empty(), "key_id must be non-empty");
        // Validate the kid against v2 string rules so a generated signer
        // can never produce a pin a strict verifier would reject.
        check_string_safe(&key_id, "key_id").expect("key_id contains unsafe chars");
        check_nfc(&key_id, "key_id").expect("key_id is not NFC");
        let mut rng = rand::rngs::OsRng;
        Signer {
            signing_key: SigningKey::generate(&mut rng),
            key_id,
        }
    }

    /// Load a signer from a 32-byte raw Ed25519 private seed.
    pub fn from_private_bytes(raw: &[u8], key_id: String) -> Result<Self, SignerError> {
        if key_id.is_empty() {
            return Err(SignerError::EmptyKeyId);
        }
        let nfc: String = key_id.nfc().collect();
        check_string_safe(&nfc, "key_id")?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| SignerError::BadKeyLength(raw.len()))?;
        Ok(Signer {
            signing_key: SigningKey::from_bytes(&bytes),
            key_id: nfc,
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

    /// 32-byte raw Ed25519 private seed. Treat as a secret.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Create a [`Pin`] for `(source, model, vector)`.
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
            return Err(SignerError::InvalidVector("empty vector".into()));
        }

        // NaN/Inf rejection per §3.2.
        if !vector_is_finite(vector) {
            return Err(SignerError::InvalidVector(
                "vector contains NaN or infinity".into(),
            ));
        }

        let dtype = opts.dtype.unwrap_or_else(|| vector.native_dtype());

        // NFC normalize string inputs and reject structurally hostile chars.
        // The signer tolerates non-NFC input (it normalizes) but rejects
        // control chars and bidi overrides so the produced pin always
        // parses under the strict verifier.
        let model_nfc: String = model.nfc().collect();
        check_string_safe(&model_nfc, "model")?;
        if model_nfc.is_empty() {
            return Err(SignerError::InvalidString(AttestationError::InvalidField {
                field: "model",
                detail: "must be non-empty".into(),
            }));
        }

        let source_nfc: String = source.nfc().collect();

        let mut extra_nfc: BTreeMap<String, String> = BTreeMap::new();
        for (k, val) in &opts.extra {
            let k_nfc: String = k.nfc().collect();
            let v_nfc: String = val.nfc().collect();
            check_string_safe(&k_nfc, "extra key")?;
            check_string_safe(&v_nfc, "extra value")?;
            extra_nfc.insert(k_nfc, v_nfc);
        }

        let ts = opts.timestamp.unwrap_or_else(now_utc_iso8601);
        // Defensive: even when we generate the timestamp ourselves, run it
        // through the same validators a parser would so locale bugs cannot
        // sneak a malformed string through.
        check_string_safe(&ts, "ts")?;
        check_nfc(&ts, "ts")?;

        let header = PinHeader {
            v: PROTOCOL_VERSION,
            kid: self.key_id.clone(),
            model: model_nfc,
            model_hash: opts.model_hash,
            source_hash: hash_text(&source_nfc),
            vec_hash: hash_vector(vector, dtype),
            vec_dtype: dtype.as_str().to_owned(),
            vec_dim: vector.len() as u32,
            ts,
            extra: extra_nfc,
        };

        let signature = self.signing_key.sign(&header.canonicalize());
        Ok(Pin {
            header,
            sig: signature.to_bytes().to_vec(),
        })
    }
}

fn vector_is_finite(v: VectorRef<'_>) -> bool {
    match v {
        VectorRef::F32(xs) => xs.iter().all(|x| x.is_finite()),
        VectorRef::F64(xs) => xs.iter().all(|x| x.is_finite()),
    }
}

/// Optional knobs for [`Signer::pin_with_options`].
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
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, se) = unix_to_ymdhms(secs as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{se:02}Z")
}

fn unix_to_ymdhms(t: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (t.div_euclid(86400)) as i32;
    let secs_of_day = t.rem_euclid(86400) as u32;
    let h = secs_of_day / 3600;
    let mi = (secs_of_day % 3600) / 60;
    let se = secs_of_day % 60;

    // Civil from days — howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, se)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_round_trip_basic() {
        let signer = Signer::generate("test".into());
        let v: Vec<f32> = vec![1.0, 2.0, 3.0];
        let pin = signer.pin("hello", "model", v.as_slice()).unwrap();
        assert_eq!(pin.kid(), "test");
        assert_eq!(pin.header.v, PROTOCOL_VERSION);
        assert_eq!(pin.header.vec_dim, 3);
        assert_eq!(pin.header.vec_dtype, "f32");
        assert_eq!(pin.sig.len(), 64);
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
    fn signer_rejects_nan() {
        let signer = Signer::generate("k".into());
        let v: Vec<f32> = vec![1.0, f32::NAN, 3.0];
        let err = signer.pin("x", "m", v.as_slice()).unwrap_err();
        assert!(matches!(err, SignerError::InvalidVector(_)));
    }

    #[test]
    fn signer_rejects_infinity() {
        let signer = Signer::generate("k".into());
        let v: Vec<f64> = vec![1.0, f64::INFINITY];
        let err = signer.pin("x", "m", v.as_slice()).unwrap_err();
        assert!(matches!(err, SignerError::InvalidVector(_)));
    }
}
