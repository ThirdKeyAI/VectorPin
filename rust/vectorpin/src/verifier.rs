// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Pin verification (protocol v2).
//!
//! The default [`Verifier`] accepts only v2 pins. [`LegacyV1Verifier`]
//! is an opt-in migration aid that additionally accepts v1 pins by
//! dispatching them to the legacy canonicalization in
//! [`crate::attestation::legacy_v1`].
//!
//! [`VerifyError`] mirrors the failure-mode set in spec §5 so callers
//! can route distinct outcomes (forgery, tamper, mismatch, parse error)
//! to different handlers.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

use crate::attestation::{
    legacy_v1::{canonicalize_v1, parse_v1_pin, V1_PROTOCOL_VERSION},
    AttestationError, Pin, PROTOCOL_VERSION,
};
use crate::hash::{hash_text, hash_vector, VecDtype, VectorRef};

/// Distinct verification failure modes (spec §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Pin uses a protocol version this verifier does not understand.
    UnsupportedVersion(u32),
    /// `kid` not present in the verifier's key registry.
    UnknownKey(String),
    /// `kid` is registered but its validity window excludes the pin's `ts`.
    KeyExpired,
    /// Pin failed wire-format / size / format validation before any
    /// cryptographic work was attempted.
    ParseError(String),
    /// Ed25519 signature did not verify against the canonical header.
    SignatureInvalid,
    /// Vector hash mismatch — embedding modified after pinning.
    VectorTampered,
    /// Source text hash mismatch.
    SourceMismatch,
    /// Pin issued for a different model than the caller expected.
    ModelMismatch {
        /// Model identifier in the pin.
        pin_model: String,
        /// Identifier the caller required.
        expected: String,
    },
    /// Supplied vector's dim did not match the pin's `vec_dim`.
    ShapeMismatch {
        /// Length of the supplied vector.
        supplied: usize,
        /// `vec_dim` from the pin header.
        expected: u32,
    },
    /// Caller's expected `vectorpin.record_id` did not match the pin.
    RecordMismatch,
    /// Caller's expected `vectorpin.collection_id` did not match the pin.
    CollectionMismatch,
    /// Caller's expected `vectorpin.tenant_id` did not match the pin.
    TenantMismatch,
    /// Pin's `vec_dtype` is not understood by this build.
    UnsupportedDtype(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::UnsupportedVersion(v) => write!(f, "unsupported pin version: {v}"),
            VerifyError::UnknownKey(k) => write!(f, "unknown signing key id: {k}"),
            VerifyError::KeyExpired => {
                write!(f, "pin ts falls outside the key's validity window")
            }
            VerifyError::ParseError(s) => write!(f, "pin parse error: {s}"),
            VerifyError::SignatureInvalid => write!(f, "ed25519 signature did not verify"),
            VerifyError::VectorTampered => {
                write!(f, "vector hash mismatch — embedding modified after pinning")
            }
            VerifyError::SourceMismatch => write!(f, "source hash mismatch"),
            VerifyError::ModelMismatch {
                pin_model,
                expected,
            } => write!(f, "pin model {pin_model:?} != expected {expected:?}"),
            VerifyError::ShapeMismatch { supplied, expected } => write!(
                f,
                "vector shape mismatch: supplied len {supplied}, pin dim {expected}"
            ),
            VerifyError::RecordMismatch => write!(f, "vectorpin.record_id mismatch"),
            VerifyError::CollectionMismatch => write!(f, "vectorpin.collection_id mismatch"),
            VerifyError::TenantMismatch => write!(f, "vectorpin.tenant_id mismatch"),
            VerifyError::UnsupportedDtype(s) => write!(f, "unsupported canonical dtype: {s}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<AttestationError> for VerifyError {
    fn from(e: AttestationError) -> Self {
        match e {
            AttestationError::UnsupportedVersion { got, .. } => VerifyError::UnsupportedVersion(got),
            other => VerifyError::ParseError(other.to_string()),
        }
    }
}

/// A registered public key plus an optional validity window (§7).
///
/// `valid_from` is inclusive, `valid_until` is exclusive. If both are
/// `None`, the key validates pins of any timestamp.
#[derive(Debug, Clone)]
pub struct KeyEntry {
    /// 32-byte Ed25519 public key.
    pub public_key: VerifyingKey,
    /// Earliest `ts` (inclusive) accepted under this key. UNIX epoch seconds.
    pub valid_from: Option<i64>,
    /// Latest `ts` (exclusive) accepted under this key. UNIX epoch seconds.
    pub valid_until: Option<i64>,
}

impl KeyEntry {
    /// Create a `KeyEntry` with no validity window.
    pub fn new(public_key: VerifyingKey) -> Self {
        Self {
            public_key,
            valid_from: None,
            valid_until: None,
        }
    }

    /// Construct from raw 32-byte public-key material.
    pub fn from_public_bytes(raw: [u8; 32]) -> Result<Self, VerifyError> {
        VerifyingKey::from_bytes(&raw)
            .map(Self::new)
            .map_err(|_| VerifyError::ParseError("invalid Ed25519 public key bytes".into()))
    }

    /// Builder: attach a `valid_from` lower bound (inclusive).
    pub fn with_valid_from(mut self, ts_unix_seconds: i64) -> Self {
        self.valid_from = Some(ts_unix_seconds);
        self
    }

    /// Builder: attach a `valid_until` upper bound (exclusive).
    pub fn with_valid_until(mut self, ts_unix_seconds: i64) -> Self {
        self.valid_until = Some(ts_unix_seconds);
        self
    }
}

/// Optional caller-supplied ground truth and replay-protection IDs.
///
/// Each field is independent: leave it `None` to skip that check.
#[derive(Debug, Default, Clone)]
pub struct VerifyOptions<'a> {
    /// Ground-truth source text. If supplied, must hash to `source_hash`.
    pub source: Option<&'a str>,
    /// Ground-truth vector. If supplied, must hash to `vec_hash`.
    pub vector: Option<VectorRef<'a>>,
    /// Expected model identifier.
    pub expected_model: Option<&'a str>,
    /// Expected `vectorpin.record_id` in `extra`.
    pub expected_record_id: Option<&'a str>,
    /// Expected `vectorpin.collection_id` in `extra`.
    pub expected_collection_id: Option<&'a str>,
    /// Expected `vectorpin.tenant_id` in `extra`.
    pub expected_tenant_id: Option<&'a str>,
}

/// Holds the public-key registry and runs pin verification against
/// supplied ground truth.
#[derive(Default)]
pub struct Verifier {
    keys: HashMap<String, KeyEntry>,
    accept_v1: bool,
}

impl Verifier {
    /// Construct an empty default verifier (v2-only).
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a public key under `kid` with no validity window.
    pub fn add_key(&mut self, kid: &str, public_key_bytes: [u8; 32]) {
        if let Ok(vk) = VerifyingKey::from_bytes(&public_key_bytes) {
            self.keys.insert(kid.to_owned(), KeyEntry::new(vk));
        }
    }

    /// Register a fully-specified [`KeyEntry`] under `kid`.
    pub fn add_key_entry(&mut self, kid: &str, entry: KeyEntry) {
        self.keys.insert(kid.to_owned(), entry);
    }

    /// Number of registered keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Verify just the signature — useful when ground-truth source/vector
    /// are unavailable but producer identity still matters.
    pub fn verify_signature(&self, pin: &Pin) -> Result<(), VerifyError> {
        self.verify(pin, VerifyOptions::default())
    }

    /// Convenience: verify with ground-truth source/vector/model.
    ///
    /// Preserved for parity with v1 callers; equivalent to building a
    /// [`VerifyOptions`] and calling [`Self::verify`].
    pub fn verify_full<'a, V>(
        &self,
        pin: &Pin,
        source: Option<&'a str>,
        vector: Option<V>,
        expected_model: Option<&'a str>,
    ) -> Result<(), VerifyError>
    where
        V: Into<VectorRef<'a>>,
    {
        self.verify(
            pin,
            VerifyOptions {
                source,
                vector: vector.map(Into::into),
                expected_model,
                ..VerifyOptions::default()
            },
        )
    }

    /// Full verification: signature + any supplied ground truth + any
    /// supplied replay-protection identifiers.
    pub fn verify(&self, pin: &Pin, opts: VerifyOptions<'_>) -> Result<(), VerifyError> {
        // Step 1: version dispatch.
        if pin.header.v != PROTOCOL_VERSION
            && !(self.accept_v1 && pin.header.v == V1_PROTOCOL_VERSION)
        {
            return Err(VerifyError::UnsupportedVersion(pin.header.v));
        }

        // Defensive: sig length is checked at parse time, but verify
        // before any signature work too so a hand-built Pin can't crash
        // the ed25519 library.
        if pin.sig.len() != 64 {
            return Err(VerifyError::ParseError(format!(
                "sig must be exactly 64 bytes; got {}",
                pin.sig.len()
            )));
        }

        // Step 2: kid lookup + validity window.
        let entry = self
            .keys
            .get(&pin.header.kid)
            .ok_or_else(|| VerifyError::UnknownKey(pin.header.kid.clone()))?;

        if entry.valid_from.is_some() || entry.valid_until.is_some() {
            let pin_ts = parse_v2_ts_unix(&pin.header.ts).ok_or(VerifyError::KeyExpired)?;
            if let Some(vf) = entry.valid_from {
                if pin_ts < vf {
                    return Err(VerifyError::KeyExpired);
                }
            }
            if let Some(vu) = entry.valid_until {
                if pin_ts >= vu {
                    return Err(VerifyError::KeyExpired);
                }
            }
        }

        // Step 4: signature.
        let canonical = canonical_for(pin);
        let sig_bytes: [u8; 64] = pin
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::SignatureInvalid)?;
        let signature = Signature::from_bytes(&sig_bytes);
        entry
            .public_key
            .verify(&canonical, &signature)
            .map_err(|_| VerifyError::SignatureInvalid)?;

        // Step 6: vector check.
        if let Some(vec) = opts.vector {
            if vec.len() as u32 != pin.header.vec_dim {
                return Err(VerifyError::ShapeMismatch {
                    supplied: vec.len(),
                    expected: pin.header.vec_dim,
                });
            }
            if !vector_is_finite(vec) {
                return Err(VerifyError::ParseError(
                    "supplied vector contains NaN or infinity".into(),
                ));
            }
            let dtype = VecDtype::parse(&pin.header.vec_dtype)
                .map_err(|_| VerifyError::UnsupportedDtype(pin.header.vec_dtype.clone()))?;
            if hash_vector(vec, dtype) != pin.header.vec_hash {
                return Err(VerifyError::VectorTampered);
            }
        }

        // Step 5: source check.
        if let Some(s) = opts.source {
            if hash_text(s) != pin.header.source_hash {
                return Err(VerifyError::SourceMismatch);
            }
        }

        // Step 7: model check.
        if let Some(em) = opts.expected_model {
            if pin.header.model != em {
                return Err(VerifyError::ModelMismatch {
                    pin_model: pin.header.model.clone(),
                    expected: em.to_owned(),
                });
            }
        }

        // Step 8: replay-protection identifier checks.
        if let Some(expected) = opts.expected_record_id {
            if pin.header.extra.get("vectorpin.record_id").map(|s| s.as_str()) != Some(expected) {
                return Err(VerifyError::RecordMismatch);
            }
        }
        if let Some(expected) = opts.expected_collection_id {
            if pin
                .header
                .extra
                .get("vectorpin.collection_id")
                .map(|s| s.as_str())
                != Some(expected)
            {
                return Err(VerifyError::CollectionMismatch);
            }
        }
        if let Some(expected) = opts.expected_tenant_id {
            if pin.header.extra.get("vectorpin.tenant_id").map(|s| s.as_str()) != Some(expected) {
                return Err(VerifyError::TenantMismatch);
            }
        }

        Ok(())
    }
}

/// Verifier that additionally accepts protocol-v1 pins via legacy
/// canonicalization. Opt-in per spec §5 step 1.
pub struct LegacyV1Verifier {
    inner: Verifier,
}

impl LegacyV1Verifier {
    /// Construct an empty legacy verifier.
    pub fn new() -> Self {
        let mut inner = Verifier::new();
        inner.accept_v1 = true;
        Self { inner }
    }

    /// Forwarded: register a public key.
    pub fn add_key(&mut self, kid: &str, public_key_bytes: [u8; 32]) {
        self.inner.add_key(kid, public_key_bytes);
    }

    /// Forwarded: register a [`KeyEntry`] with optional validity window.
    pub fn add_key_entry(&mut self, kid: &str, entry: KeyEntry) {
        self.inner.add_key_entry(kid, entry);
    }

    /// Verify a parsed pin (v1 or v2).
    pub fn verify(&self, pin: &Pin, opts: VerifyOptions<'_>) -> Result<(), VerifyError> {
        self.inner.verify(pin, opts)
    }

    /// Parse a v1 or v2 pin JSON string. v1 pins go through the looser
    /// v1 parser; v2 pins are parsed strictly.
    pub fn parse_pin(s: &str) -> Result<Pin, VerifyError> {
        // Cheap peek at the version field to choose the right parser.
        let value: serde_json::Value = serde_json::from_str(s)
            .map_err(|e| VerifyError::ParseError(format!("JSON parse: {e}")))?;
        let v = value
            .get("v")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| VerifyError::ParseError("missing `v` field".into()))?
            as u32;
        if v == V1_PROTOCOL_VERSION {
            parse_v1_pin(s).map_err(VerifyError::from)
        } else {
            Pin::from_value(value).map_err(VerifyError::from)
        }
    }
}

impl Default for LegacyV1Verifier {
    fn default() -> Self {
        Self::new()
    }
}

fn canonical_for(pin: &Pin) -> Vec<u8> {
    if pin.header.v == V1_PROTOCOL_VERSION {
        canonicalize_v1(&pin.header)
    } else {
        pin.header.canonicalize()
    }
}

fn vector_is_finite(v: VectorRef<'_>) -> bool {
    match v {
        VectorRef::F32(xs) => xs.iter().all(|x| x.is_finite()),
        VectorRef::F64(xs) => xs.iter().all(|x| x.is_finite()),
    }
}

/// Parse a v2-format `ts` string to UNIX epoch seconds. Returns `None`
/// on any format violation (callers map this to [`VerifyError::KeyExpired`]
/// to avoid leaking parser-internal errors from the validity-window path).
fn parse_v2_ts_unix(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let n2 = |i: usize| -> Option<i64> {
        let a = b[i];
        let c = b[i + 1];
        if a.is_ascii_digit() && c.is_ascii_digit() {
            Some(((a - b'0') * 10 + (c - b'0')) as i64)
        } else {
            None
        }
    };
    let n4 = |i: usize| -> Option<i64> {
        let mut acc = 0i64;
        for j in 0..4 {
            let c = b[i + j];
            if !c.is_ascii_digit() {
                return None;
            }
            acc = acc * 10 + (c - b'0') as i64;
        }
        Some(acc)
    };
    let year = n4(0)? as i32;
    let month = n2(5)? as u32;
    let day = n2(8)? as u32;
    let hour = n2(11)? as u32;
    let minute = n2(14)? as u32;
    let second = n2(17)? as u32;
    Some(civil_to_unix(year, month, day, hour, minute, second))
}

fn civil_to_unix(y: i32, m: u32, d: u32, h: u32, mi: u32, s: u32) -> i64 {
    // Inverse of unix_to_ymdhms (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let m_u = m as i32;
    let doy = (153 * (if m_u > 2 { m_u - 3 } else { m_u + 9 }) as u32 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era as i64 * 146097 + doe as i64 - 719468;
    days * 86400 + (h as i64) * 3600 + (mi as i64) * 60 + (s as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Signer;

    fn fixture(kid: &str) -> (Signer, Verifier, Vec<f32>) {
        let signer = Signer::generate(kid.into());
        let mut verifier = Verifier::new();
        verifier.add_key(signer.key_id(), signer.public_key_bytes());
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
        let signer = Signer::generate("rogue".into());
        let v: Vec<f32> = vec![1.0, 2.0, 3.0];
        let pin = signer.pin("x", "m", v.as_slice()).unwrap();
        let other = Signer::generate("prod".into());
        let mut verifier = Verifier::new();
        verifier.add_key(other.key_id(), other.public_key_bytes());
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
    fn ts_round_trip() {
        // Verify our local ts parser matches the format the signer emits.
        let unix = parse_v2_ts_unix("2026-05-05T12:00:00Z").unwrap();
        // 2026-05-05T12:00:00Z = 1777982400 (verified via Python
        // `datetime(...).timestamp()` against UTC).
        assert_eq!(unix, 1_777_982_400);
    }

    #[test]
    fn key_expired_lower_bound() {
        let signer = Signer::generate("k".into());
        let v: Vec<f32> = vec![1.0, 2.0];
        let pin = signer.pin("x", "m", v.as_slice()).unwrap();
        let pin_unix = parse_v2_ts_unix(&pin.header.ts).unwrap();

        let mut verifier = Verifier::new();
        let vk = VerifyingKey::from_bytes(&signer.public_key_bytes()).unwrap();
        verifier.add_key_entry(
            signer.key_id(),
            KeyEntry::new(vk).with_valid_from(pin_unix + 1),
        );
        let err = verifier.verify_signature(&pin).unwrap_err();
        assert_eq!(err, VerifyError::KeyExpired);
    }
}
