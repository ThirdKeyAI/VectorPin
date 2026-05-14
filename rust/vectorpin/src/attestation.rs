// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Pin attestation data structures and canonical serialization.
//!
//! A [`Pin`] is a JSON object with a header (the signed payload) plus a
//! key id and a signature. The header canonicalizes to a deterministic
//! byte sequence — sorted keys, no whitespace, raw UTF-8 (non-ASCII
//! is *not* escaped to `\uXXXX`) — that the Python, Rust, and
//! TypeScript reference implementations agree on byte-for-byte.
//!
//! That deterministic byte sequence is what gets signed by Ed25519, not
//! the JSON wire form. Re-serializing a pin (different whitespace,
//! different key order) therefore does *not* invalidate the signature
//! as long as the canonical form is recoverable.
//!
//! For the full wire-format specification — every field, every supported
//! dtype, the exact canonicalization algorithm — see
//! [`docs/spec.md`](https://github.com/ThirdKeyAI/VectorPin/blob/main/docs/spec.md).
//!
//! # Example
//!
//! ```
//! use vectorpin::{Pin, Signer};
//!
//! let signer = Signer::generate("demo".to_string()).unwrap();
//! let v: Vec<f32> = vec![1.0, 2.0, 3.0];
//! let pin = signer.pin("hello", "test-model", v.as_slice()).unwrap();
//!
//! // Compact JSON for storage in your vector DB metadata.
//! let json: String = pin.to_json();
//! assert!(!json.contains(": "));
//! assert!(!json.contains(", "));
//!
//! // Round-trip through wire form preserves the pin exactly.
//! let parsed = Pin::from_json(&json).unwrap();
//! assert_eq!(pin, parsed);
//! ```

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Protocol version implemented by this crate. Verifiers reject pins
/// whose `v` field does not match.
pub const PROTOCOL_VERSION: u32 = 1;

/// The signed portion of a [`Pin`].
///
/// Two pins are considered equivalent iff their headers canonicalize to
/// identical bytes. Optional fields ([`model_hash`](Self::model_hash),
/// [`extra`](Self::extra)) are omitted from the canonical form when
/// unset, never written as `null` — this matters because adding a
/// `null` would change the byte sequence the signature commits to.
///
/// You normally do not construct `PinHeader` directly; obtain one from
/// [`Signer::pin`](crate::Signer::pin) or
/// [`Signer::pin_with_options`](crate::signer::Signer::pin_with_options).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinHeader {
    /// Protocol version. Must equal [`PROTOCOL_VERSION`].
    pub v: u32,
    /// Embedding model identifier.
    pub model: String,
    /// Optional content hash of the model weights.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model_hash: Option<String>,
    /// SHA-256 of the source text (UTF-8 NFC).
    pub source_hash: String,
    /// SHA-256 of the embedding vector under the declared dtype.
    pub vec_hash: String,
    /// `"f32"` or `"f64"`.
    pub vec_dtype: String,
    /// Embedding dimensionality.
    pub vec_dim: u32,
    /// RFC 3339 / ISO 8601 timestamp in UTC, e.g. `"2026-05-05T12:00:00Z"`.
    pub ts: String,
    /// Producer-defined string-to-string metadata, signed alongside the
    /// rest of the header. Omitted from the canonical form when empty.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub extra: BTreeMap<String, String>,
}

impl PinHeader {
    /// Stable byte representation for signing/verifying.
    ///
    /// JSON with sorted keys and no whitespace. `BTreeMap` gives us
    /// sorted `extra` for free; field order is fixed by hand below to
    /// match the Python reference.
    pub fn canonicalize(&self) -> Vec<u8> {
        // Manually build a sorted JSON object — this is the contract the
        // Python implementation also follows. Using `serde_json::to_vec`
        // on the struct directly would emit fields in declaration order,
        // not lexicographic order, which would break compatibility.
        let mut entries: Vec<(&'static str, serde_json::Value)> = Vec::new();
        entries.push(("v", serde_json::Value::Number(self.v.into())));
        entries.push(("model", serde_json::Value::String(self.model.clone())));
        if let Some(h) = &self.model_hash {
            entries.push(("model_hash", serde_json::Value::String(h.clone())));
        }
        entries.push((
            "source_hash",
            serde_json::Value::String(self.source_hash.clone()),
        ));
        entries.push(("vec_hash", serde_json::Value::String(self.vec_hash.clone())));
        entries.push((
            "vec_dtype",
            serde_json::Value::String(self.vec_dtype.clone()),
        ));
        entries.push(("vec_dim", serde_json::Value::Number(self.vec_dim.into())));
        entries.push(("ts", serde_json::Value::String(self.ts.clone())));
        if !self.extra.is_empty() {
            // BTreeMap iterates in sorted key order; preserve that as a
            // serde_json::Map (which is also sorted in our build via the
            // preserve_order feature being OFF — the default).
            let mut m = serde_json::Map::new();
            for (k, val) in &self.extra {
                m.insert(k.clone(), serde_json::Value::String(val.clone()));
            }
            entries.push(("extra", serde_json::Value::Object(m)));
        }

        // Sort the top-level entries lexicographically. This is the rule
        // the Python implementation follows via `sort_keys=True`.
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let mut map = serde_json::Map::with_capacity(entries.len());
        for (k, v) in entries {
            map.insert(k.to_string(), v);
        }
        serde_json::to_vec(&serde_json::Value::Object(map))
            .expect("JSON serialization of well-formed map cannot fail")
    }
}

/// A signed VectorPin attestation.
///
/// Serialize with [`Pin::to_json`] and store the resulting string
/// alongside the embedding in vector-store metadata. On read, parse
/// with [`Pin::from_json`] and hand to [`Verifier::verify_full`](crate::Verifier::verify_full).
///
/// # Example
///
/// ```
/// use vectorpin::{Pin, Signer, Verifier};
///
/// let signer = Signer::generate("k1".to_string()).unwrap();
/// let v: Vec<f32> = vec![1.0, 2.0, 3.0];
/// let pin = signer.pin("hello", "m", v.as_slice()).unwrap();
///
/// let mut verifier = Verifier::new();
/// verifier.add_key(signer.key_id(), signer.public_key_bytes()).unwrap();
/// assert!(verifier.verify_signature(&Pin::from_json(&pin.to_json()).unwrap()).is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// The signed payload.
    pub header: PinHeader,
    /// Identifier of the signing key — verifiers route to a public key by `kid`.
    pub kid: String,
    /// Raw Ed25519 signature bytes (64 bytes).
    pub sig: Vec<u8>,
}

/// URL-safe base64, padding stripped, matching the Python encoder.
pub(crate) fn b64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Inverse of [`b64url_encode`]. Restores stripped padding internally.
pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>, AttestationError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(AttestationError::Base64)
}

/// Errors produced when parsing or serializing pins.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// Pin uses a protocol version this crate does not support.
    #[error("unsupported pin version: got {got}, expected {expected}")]
    UnsupportedVersion {
        /// Version number found in the pin.
        got: u32,
        /// Version number this build supports.
        expected: u32,
    },
    /// JSON parsing failure.
    #[error("malformed pin JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Base64 decode failure (signature or related field).
    #[error("malformed base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// A required field was missing from the pin JSON.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// The `extra` map contained a value that was not a JSON string.
    /// The wire format only permits string values; non-string values
    /// used to be silently dropped and are now rejected so callers see
    /// the malformed input.
    #[error("extra map value for key {0:?} is not a string")]
    ExtraTypeMismatch(String),
}

impl Pin {
    /// Encode the pin as compact JSON suitable for vector DB metadata.
    ///
    /// Output is sorted-key, whitespace-free JSON exactly matching what
    /// the Python implementation emits, so `to_json()` is deterministic
    /// across implementations.
    pub fn to_json(&self) -> String {
        let mut entries: Vec<(&str, serde_json::Value)> = Vec::new();
        entries.push(("v", serde_json::Value::Number(self.header.v.into())));
        entries.push((
            "model",
            serde_json::Value::String(self.header.model.clone()),
        ));
        if let Some(h) = &self.header.model_hash {
            entries.push(("model_hash", serde_json::Value::String(h.clone())));
        }
        entries.push((
            "source_hash",
            serde_json::Value::String(self.header.source_hash.clone()),
        ));
        entries.push((
            "vec_hash",
            serde_json::Value::String(self.header.vec_hash.clone()),
        ));
        entries.push((
            "vec_dtype",
            serde_json::Value::String(self.header.vec_dtype.clone()),
        ));
        entries.push((
            "vec_dim",
            serde_json::Value::Number(self.header.vec_dim.into()),
        ));
        entries.push(("ts", serde_json::Value::String(self.header.ts.clone())));
        if !self.header.extra.is_empty() {
            let mut m = serde_json::Map::new();
            for (k, val) in &self.header.extra {
                m.insert(k.clone(), serde_json::Value::String(val.clone()));
            }
            entries.push(("extra", serde_json::Value::Object(m)));
        }
        entries.push(("kid", serde_json::Value::String(self.kid.clone())));
        entries.push(("sig", serde_json::Value::String(b64url_encode(&self.sig))));
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let mut map = serde_json::Map::with_capacity(entries.len());
        for (k, v) in entries {
            map.insert(k.to_string(), v);
        }
        serde_json::to_string(&serde_json::Value::Object(map))
            .expect("JSON serialization of well-formed map cannot fail")
    }

    /// Parse a pin from its compact JSON wire form.
    pub fn from_json(s: &str) -> Result<Self, AttestationError> {
        let value: serde_json::Value = serde_json::from_str(s)?;
        Self::from_value(value)
    }

    /// Parse a pin from a parsed `serde_json::Value`.
    pub fn from_value(value: serde_json::Value) -> Result<Self, AttestationError> {
        let obj = value
            .as_object()
            .ok_or(AttestationError::MissingField("(root)"))?;

        let v = obj
            .get("v")
            .and_then(|x| x.as_u64())
            .ok_or(AttestationError::MissingField("v"))? as u32;
        if v != PROTOCOL_VERSION {
            return Err(AttestationError::UnsupportedVersion {
                got: v,
                expected: PROTOCOL_VERSION,
            });
        }

        fn s_field(
            obj: &serde_json::Map<String, serde_json::Value>,
            name: &'static str,
        ) -> Result<String, AttestationError> {
            obj.get(name)
                .and_then(|x| x.as_str())
                .map(str::to_owned)
                .ok_or(AttestationError::MissingField(name))
        }

        let extra: BTreeMap<String, String> = match obj.get("extra") {
            None => BTreeMap::new(),
            Some(serde_json::Value::Object(m)) => {
                let mut out = BTreeMap::new();
                for (k, v) in m {
                    match v.as_str() {
                        Some(s) => {
                            out.insert(k.clone(), s.to_owned());
                        }
                        None => {
                            return Err(AttestationError::ExtraTypeMismatch(k.clone()));
                        }
                    }
                }
                out
            }
            // Anything other than absent-or-object for `extra` is malformed.
            Some(_) => return Err(AttestationError::MissingField("extra")),
        };

        let header = PinHeader {
            v,
            model: s_field(obj, "model")?,
            model_hash: obj
                .get("model_hash")
                .and_then(|x| x.as_str())
                .map(String::from),
            source_hash: s_field(obj, "source_hash")?,
            vec_hash: s_field(obj, "vec_hash")?,
            vec_dtype: s_field(obj, "vec_dtype")?,
            vec_dim: u32::try_from(
                obj.get("vec_dim")
                    .and_then(|x| x.as_u64())
                    .ok_or(AttestationError::MissingField("vec_dim"))?,
            )
            .map_err(|_| AttestationError::MissingField("vec_dim"))?,
            ts: s_field(obj, "ts")?,
            extra,
        };

        let kid = s_field(obj, "kid")?;
        let sig = b64url_decode(s_field(obj, "sig")?.as_str())?;

        Ok(Pin { header, kid, sig })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> PinHeader {
        PinHeader {
            v: PROTOCOL_VERSION,
            model: "test-model".into(),
            model_hash: None,
            source_hash: format!("sha256:{}", "0".repeat(64)),
            vec_hash: format!("sha256:{}", "1".repeat(64)),
            vec_dtype: "f32".into(),
            vec_dim: 3072,
            ts: "2026-05-05T12:00:00Z".into(),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn canonicalize_is_deterministic() {
        let h = header();
        assert_eq!(h.canonicalize(), h.canonicalize());
    }

    #[test]
    fn canonicalize_omits_optional_when_unset() {
        let raw = String::from_utf8(header().canonicalize()).unwrap();
        assert!(!raw.contains("model_hash"));
        assert!(!raw.contains("extra"));
    }

    #[test]
    fn pin_round_trip_via_json() {
        let pin = Pin {
            header: header(),
            kid: "k".into(),
            sig: vec![1u8; 64],
        };
        let restored = Pin::from_json(&pin.to_json()).unwrap();
        assert_eq!(pin, restored);
    }

    #[test]
    fn pin_rejects_unsupported_version() {
        let bad = serde_json::json!({
            "v": 99,
            "model": "x",
            "source_hash": format!("sha256:{}", "0".repeat(64)),
            "vec_hash": format!("sha256:{}", "1".repeat(64)),
            "vec_dtype": "f32",
            "vec_dim": 1,
            "ts": "2026-05-05T12:00:00Z",
            "kid": "k",
            "sig": "AA",
        });
        let err = Pin::from_value(bad).unwrap_err();
        assert!(matches!(err, AttestationError::UnsupportedVersion { .. }));
    }

    #[test]
    fn pin_to_json_is_compact() {
        let pin = Pin {
            header: header(),
            kid: "k".into(),
            sig: vec![1u8; 64],
        };
        let j = pin.to_json();
        assert!(!j.contains(": "));
        assert!(!j.contains(", "));
    }
}
