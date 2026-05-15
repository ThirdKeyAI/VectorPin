// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Pin attestation data structures and canonical serialization (v2).
//!
//! A [`Pin`] is a JSON object whose **header** (every field except `sig`)
//! canonicalizes to a deterministic byte sequence the Ed25519 signature
//! commits to. Protocol v2 — implemented here — prepends a 13-byte
//! domain separator ([`DOMAIN_TAG`]) and binds both `v` and `kid` into
//! the signed bytes to defeat downgrade and key-swap attacks.
//!
//! See [`docs/spec.md`](https://github.com/ThirdKeyAI/VectorPin/blob/main/docs/spec.md)
//! §4.2 for the exact canonicalization rules. v2 is a wire-format break
//! with v1; a [`legacy_v1`] submodule re-emits the older canonical bytes
//! for migration verifiers only.

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};
use unicode_normalization::{is_nfc, UnicodeNormalization};

/// Protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u32 = 2;

/// Domain separator prepended to canonical JSON before signing.
///
/// Exactly 13 bytes: ASCII `"vectorpin/v2"` (12 bytes) plus one trailing
/// NUL. The spec text describes this string as "14 bytes" in §2 and §4.2
/// — that is a known typo; the byte literal is the contract. Cross-
/// language ports MUST match these bytes.
pub const DOMAIN_TAG: &[u8] = b"vectorpin/v2\x00";

// Compile-time sanity check: any edit that resizes the tag fails the build.
const _: () = assert!(DOMAIN_TAG.len() == 13);

// ---- size limits (spec §4.3) ----

/// Maximum byte length of a Pin's JSON wire form.
pub const MAX_PIN_JSON_BYTES: usize = 65_536;
/// Maximum number of entries in `extra`.
pub const MAX_EXTRA_ENTRIES: usize = 32;
/// Maximum UTF-8 byte length of any single `extra` key.
pub const MAX_EXTRA_KEY_BYTES: usize = 128;
/// Maximum UTF-8 byte length of any single `extra` value.
pub const MAX_EXTRA_VALUE_BYTES: usize = 1024;
/// Hard ceiling on `vec_dim` (2^20).
pub const MAX_VEC_DIM: u32 = 1_048_576;
/// Exact length of an Ed25519 signature in bytes.
pub const SIG_LEN: usize = 64;

/// Set of permitted top-level keys in a v2 pin (§4.1). Any other key
/// rejects at parse time.
const ALLOWED_TOP_LEVEL: &[&str] = &[
    "v",
    "kid",
    "model",
    "model_hash",
    "source_hash",
    "vec_hash",
    "vec_dtype",
    "vec_dim",
    "ts",
    "extra",
    "sig",
];

const ALLOWED_DTYPES: &[&str] = &["f32", "f64"];

/// The signed portion of a [`Pin`].
///
/// Carries `v` and `kid` — both are part of the v2 canonical bytes
/// (§4.2) so the signature commits to them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinHeader {
    /// Protocol version. MUST equal [`PROTOCOL_VERSION`] for new pins.
    pub v: u32,
    /// Signing-key identifier — bound into the signature in v2.
    pub kid: String,
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
    /// UTC timestamp matching `YYYY-MM-DDTHH:MM:SSZ` exactly.
    pub ts: String,
    /// Producer-defined string-to-string metadata. Signed alongside the
    /// rest of the header. Omitted from the canonical form when empty.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub extra: BTreeMap<String, String>,
}

impl PinHeader {
    /// Stable byte representation for signing/verifying.
    ///
    /// Returns `DOMAIN_TAG || canonical_json(header)` where the JSON has
    /// lexicographically sorted keys, no whitespace, and raw UTF-8 (not
    /// `\uXXXX`) for any non-ASCII code points that are not in the
    /// JSON-mandatory escape set. NFC normalization is applied to every
    /// string field at canonicalization time so the bytes match what a
    /// fresh-from-spec implementation would emit.
    pub fn canonicalize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DOMAIN_TAG.len() + 256);
        out.extend_from_slice(DOMAIN_TAG);
        out.extend_from_slice(&self.canonical_json_body());
        out
    }

    fn canonical_json_body(&self) -> Vec<u8> {
        // BTreeMap iterates in sorted key order; serde_json (default
        // build, no preserve_order) preserves insertion order — so we
        // build a Map by inserting in lexicographic order ourselves.
        let mut entries: Vec<(&str, serde_json::Value)> = Vec::new();
        entries.push(("v", serde_json::Value::Number(self.v.into())));
        entries.push(("kid", serde_json::Value::String(nfc_string(&self.kid))));
        entries.push(("model", serde_json::Value::String(nfc_string(&self.model))));
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
        entries.push(("ts", serde_json::Value::String(nfc_string(&self.ts))));
        if !self.extra.is_empty() {
            // NFC each key and value, then re-sort by NFC'd key.
            let mut nfc_entries: Vec<(String, String)> = self
                .extra
                .iter()
                .map(|(k, v)| (nfc_string(k), nfc_string(v)))
                .collect();
            nfc_entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut m = serde_json::Map::new();
            for (k, val) in nfc_entries {
                m.insert(k, serde_json::Value::String(val));
            }
            entries.push(("extra", serde_json::Value::Object(m)));
        }
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let mut map = serde_json::Map::with_capacity(entries.len());
        for (k, v) in entries {
            map.insert(k.to_string(), v);
        }
        serde_json::to_vec(&serde_json::Value::Object(map))
            .expect("JSON serialization of well-formed map cannot fail")
    }
}

fn nfc_string(s: &str) -> String {
    s.nfc().collect()
}

/// A signed VectorPin attestation.
///
/// Serialize with [`Pin::to_json`] and store alongside the embedding in
/// vector-store metadata. On read, parse with [`Pin::from_json`] and
/// hand to [`Verifier::verify`](crate::Verifier::verify) (or one of its
/// convenience wrappers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// The signed payload, including `v` and `kid`.
    pub header: PinHeader,
    /// Raw Ed25519 signature bytes (exactly 64 bytes).
    pub sig: Vec<u8>,
}

impl Pin {
    /// Convenience accessor — `kid` lives on the header in v2.
    pub fn kid(&self) -> &str {
        &self.header.kid
    }

    /// Compact JSON encoding suitable for vector-DB metadata.
    pub fn to_json(&self) -> String {
        let mut entries: Vec<(&str, serde_json::Value)> = Vec::new();
        entries.push(("v", serde_json::Value::Number(self.header.v.into())));
        entries.push(("kid", serde_json::Value::String(self.header.kid.clone())));
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
        entries.push(("sig", serde_json::Value::String(b64url_encode(&self.sig))));
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let mut map = serde_json::Map::with_capacity(entries.len());
        for (k, v) in entries {
            map.insert(k.to_string(), v);
        }
        serde_json::to_string(&serde_json::Value::Object(map))
            .expect("JSON serialization of well-formed map cannot fail")
    }

    /// Parse a pin from its compact JSON wire form, enforcing every v2
    /// wire-format rule (§4.1, §4.3, §3.1).
    pub fn from_json(s: &str) -> Result<Self, AttestationError> {
        // Pre-parse size check (§4.3). Reject before allocating the parse tree.
        if s.len() > MAX_PIN_JSON_BYTES {
            return Err(AttestationError::SizeLimit {
                limit: MAX_PIN_JSON_BYTES,
                got: s.len(),
            });
        }
        let value: serde_json::Value = serde_json::from_str(s).map_err(AttestationError::Json)?;
        Self::from_value(value)
    }

    /// Parse a pin from a parsed `serde_json::Value`. Same validation
    /// rules as [`Pin::from_json`].
    pub fn from_value(value: serde_json::Value) -> Result<Self, AttestationError> {
        parse_pin_strict(value, PROTOCOL_VERSION)
    }
}

/// URL-safe base64, padding stripped — matches every other reference port.
pub(crate) fn b64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>, AttestationError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(AttestationError::Base64)
}

/// Errors produced when parsing, serializing, or canonicalizing pins.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// Pin uses a protocol version this code path does not accept.
    #[error("unsupported pin version: got {got}, expected {expected}")]
    UnsupportedVersion {
        /// Version number found in the pin.
        got: u32,
        /// Version this build accepts.
        expected: u32,
    },
    /// JSON parsing failure.
    #[error("malformed pin JSON: {0}")]
    Json(#[source] serde_json::Error),
    /// Base64 decode failure (signature or related field).
    #[error("malformed base64: {0}")]
    Base64(#[source] base64::DecodeError),
    /// A required field was missing from the pin JSON.
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    /// A field had the wrong JSON type or violated a format rule.
    #[error("invalid field {field}: {detail}")]
    InvalidField {
        /// Name of the offending field.
        field: &'static str,
        /// Human-readable explanation.
        detail: String,
    },
    /// Pin contains a top-level key outside the v2 allow-list.
    #[error("unknown top-level field: {0}")]
    UnknownTopLevelField(String),
    /// A string-typed field was not in Unicode NFC form.
    #[error("field is not NFC-normalized: {0}")]
    NotNfc(String),
    /// A string-typed field contained a control character (U+0000..U+001F).
    #[error("field contains control character: {0}")]
    ControlChar(String),
    /// A string-typed field contained a bidi override (U+202A..U+202E / U+2066..U+2069).
    #[error("field contains bidi-override character: {0}")]
    BidiOverride(String),
    /// `ts` did not match `^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}Z$`.
    #[error("bad timestamp format: {0}")]
    BadTimestamp(String),
    /// Pin (or a sub-field) exceeded a size cap from §4.3.
    #[error("size limit exceeded: limit={limit}, got={got}")]
    SizeLimit {
        /// Configured cap.
        limit: usize,
        /// Observed value.
        got: usize,
    },
}

/// Hash-string format: `sha256:` followed by exactly 64 lowercase hex chars.
fn is_valid_hash_string(s: &str) -> bool {
    if !s.starts_with("sha256:") {
        return false;
    }
    let hex = &s[7..];
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Timestamp regex: `YYYY-MM-DDTHH:MM:SSZ`, exactly.
fn is_valid_ts(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20 {
        return false;
    }
    let dig = |i: usize| b[i].is_ascii_digit();
    dig(0)
        && dig(1)
        && dig(2)
        && dig(3)
        && b[4] == b'-'
        && dig(5)
        && dig(6)
        && b[7] == b'-'
        && dig(8)
        && dig(9)
        && b[10] == b'T'
        && dig(11)
        && dig(12)
        && b[13] == b':'
        && dig(14)
        && dig(15)
        && b[16] == b':'
        && dig(17)
        && dig(18)
        && b[19] == b'Z'
}

/// Reject control chars (U+0000-U+001F) and bidi overrides
/// (U+202A-U+202E, U+2066-U+2069) per §3.1.
pub(crate) fn check_string_safe(value: &str, field: &str) -> Result<(), AttestationError> {
    for ch in value.chars() {
        let cp = ch as u32;
        if cp < 0x20 {
            return Err(AttestationError::ControlChar(format!(
                "{field}: U+{cp:04X}"
            )));
        }
        if (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp) {
            return Err(AttestationError::BidiOverride(format!(
                "{field}: U+{cp:04X}"
            )));
        }
    }
    Ok(())
}

/// Reject strings not already in NFC form.
pub(crate) fn check_nfc(value: &str, field: &str) -> Result<(), AttestationError> {
    if !is_nfc(value) {
        Err(AttestationError::NotNfc(field.to_string()))
    } else {
        Ok(())
    }
}

fn parse_pin_strict(
    value: serde_json::Value,
    expected_version: u32,
) -> Result<Pin, AttestationError> {
    let obj = match value {
        serde_json::Value::Object(m) => m,
        _ => {
            return Err(AttestationError::InvalidField {
                field: "(root)",
                detail: "pin must be a JSON object".into(),
            })
        }
    };

    // 1. Reject unknown top-level fields (§4.1).
    for k in obj.keys() {
        if !ALLOWED_TOP_LEVEL.iter().any(|allowed| allowed == k) {
            return Err(AttestationError::UnknownTopLevelField(k.clone()));
        }
    }

    // 2. Version check.
    let v_raw = obj
        .get("v")
        .ok_or(AttestationError::MissingField("v"))?
        .as_u64()
        .ok_or(AttestationError::InvalidField {
            field: "v",
            detail: "must be an unsigned integer".into(),
        })?;
    let v = v_raw as u32;
    if v != expected_version {
        return Err(AttestationError::UnsupportedVersion {
            got: v,
            expected: expected_version,
        });
    }

    // 3. String fields with NFC + control-char + bidi checks.
    let kid = string_field(&obj, "kid")?;
    check_string_safe(&kid, "kid")?;
    check_nfc(&kid, "kid")?;

    let model = string_field(&obj, "model")?;
    check_string_safe(&model, "model")?;
    check_nfc(&model, "model")?;

    let ts = string_field(&obj, "ts")?;
    if !is_valid_ts(&ts) {
        return Err(AttestationError::BadTimestamp(ts));
    }
    check_string_safe(&ts, "ts")?;
    check_nfc(&ts, "ts")?;

    // 4. Hashes.
    let source_hash = string_field(&obj, "source_hash")?;
    if !is_valid_hash_string(&source_hash) {
        return Err(AttestationError::InvalidField {
            field: "source_hash",
            detail: "must match 'sha256:<64 lowercase hex>'".into(),
        });
    }
    let vec_hash = string_field(&obj, "vec_hash")?;
    if !is_valid_hash_string(&vec_hash) {
        return Err(AttestationError::InvalidField {
            field: "vec_hash",
            detail: "must match 'sha256:<64 lowercase hex>'".into(),
        });
    }
    let model_hash = match obj.get("model_hash") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => {
            if !is_valid_hash_string(s) {
                return Err(AttestationError::InvalidField {
                    field: "model_hash",
                    detail: "must match 'sha256:<64 lowercase hex>'".into(),
                });
            }
            Some(s.clone())
        }
        Some(_) => {
            return Err(AttestationError::InvalidField {
                field: "model_hash",
                detail: "must be a string when present".into(),
            })
        }
    };

    // 5. vec_dtype / vec_dim.
    let vec_dtype = string_field(&obj, "vec_dtype")?;
    if !ALLOWED_DTYPES.contains(&vec_dtype.as_str()) {
        return Err(AttestationError::InvalidField {
            field: "vec_dtype",
            detail: format!("must be one of {ALLOWED_DTYPES:?}; got {vec_dtype:?}"),
        });
    }

    // bool is JSON-distinct from integer in serde_json, but be defensive.
    let vec_dim_raw = obj
        .get("vec_dim")
        .ok_or(AttestationError::MissingField("vec_dim"))?;
    if vec_dim_raw.is_boolean() {
        return Err(AttestationError::InvalidField {
            field: "vec_dim",
            detail: "must be an integer, not a boolean".into(),
        });
    }
    let vec_dim_u64 = vec_dim_raw.as_u64().ok_or(AttestationError::InvalidField {
        field: "vec_dim",
        detail: "must be a positive integer".into(),
    })?;
    if vec_dim_u64 == 0 || vec_dim_u64 > MAX_VEC_DIM as u64 {
        return Err(AttestationError::InvalidField {
            field: "vec_dim",
            detail: format!("must be in (0, {MAX_VEC_DIM}]; got {vec_dim_u64}"),
        });
    }
    let vec_dim = vec_dim_u64 as u32;

    // 6. extra: map<string, string>, bounded.
    let extra = match obj.get("extra") {
        None | Some(serde_json::Value::Null) => BTreeMap::new(),
        Some(serde_json::Value::Object(m)) => {
            if m.len() > MAX_EXTRA_ENTRIES {
                return Err(AttestationError::SizeLimit {
                    limit: MAX_EXTRA_ENTRIES,
                    got: m.len(),
                });
            }
            let mut out = BTreeMap::new();
            for (k, val) in m {
                let val_s = val.as_str().ok_or(AttestationError::InvalidField {
                    field: "extra",
                    detail: format!("value for key {k:?} must be a string"),
                })?;
                if k.len() > MAX_EXTRA_KEY_BYTES {
                    return Err(AttestationError::SizeLimit {
                        limit: MAX_EXTRA_KEY_BYTES,
                        got: k.len(),
                    });
                }
                if val_s.len() > MAX_EXTRA_VALUE_BYTES {
                    return Err(AttestationError::SizeLimit {
                        limit: MAX_EXTRA_VALUE_BYTES,
                        got: val_s.len(),
                    });
                }
                check_string_safe(k, "extra key")?;
                check_nfc(k, "extra key")?;
                check_string_safe(val_s, "extra value")?;
                check_nfc(val_s, "extra value")?;
                out.insert(k.clone(), val_s.to_string());
            }
            out
        }
        Some(_) => {
            return Err(AttestationError::InvalidField {
                field: "extra",
                detail: "must be a JSON object".into(),
            })
        }
    };

    // 7. Signature: base64, exactly 64 bytes.
    let sig_str = string_field(&obj, "sig")?;
    let sig = b64url_decode(&sig_str)?;
    if sig.len() != SIG_LEN {
        return Err(AttestationError::InvalidField {
            field: "sig",
            detail: format!("must decode to exactly {SIG_LEN} bytes; got {}", sig.len()),
        });
    }

    Ok(Pin {
        header: PinHeader {
            v,
            kid,
            model,
            model_hash,
            source_hash,
            vec_hash,
            vec_dtype,
            vec_dim,
            ts,
            extra,
        },
        sig,
    })
}

fn string_field(
    obj: &serde_json::Map<String, serde_json::Value>,
    name: &'static str,
) -> Result<String, AttestationError> {
    match obj.get(name) {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        Some(serde_json::Value::String(_)) => Err(AttestationError::InvalidField {
            field: name,
            detail: "must be a non-empty string".into(),
        }),
        Some(_) => Err(AttestationError::InvalidField {
            field: name,
            detail: "must be a string".into(),
        }),
        None => Err(AttestationError::MissingField(name)),
    }
}

/// Legacy v1 canonicalization, kept exclusively for the opt-in migration
/// verifier. v1 pins are NOT accepted by the default parser.
pub mod legacy_v1 {
    use super::*;

    /// v1 protocol version constant. Distinct from [`PROTOCOL_VERSION`]
    /// so callers cannot accidentally confuse the two.
    pub const V1_PROTOCOL_VERSION: u32 = 1;

    /// Reconstruct v1 canonical bytes for a parsed v1 pin.
    ///
    /// v1 differed from v2 in three load-bearing ways:
    /// - No domain-tag prefix.
    /// - `kid` was NOT in the signed bytes.
    /// - No strict NFC / control-char / bidi enforcement at parse time.
    ///
    /// The byte sequence emitted here matches what the Python v1 reference
    /// emitted, so historical pins continue to verify against their
    /// original signatures.
    pub fn canonicalize_v1(header: &PinHeader) -> Vec<u8> {
        let mut entries: Vec<(&str, serde_json::Value)> = Vec::new();
        entries.push(("v", serde_json::Value::Number(header.v.into())));
        entries.push(("model", serde_json::Value::String(header.model.clone())));
        if let Some(h) = &header.model_hash {
            entries.push(("model_hash", serde_json::Value::String(h.clone())));
        }
        entries.push((
            "source_hash",
            serde_json::Value::String(header.source_hash.clone()),
        ));
        entries.push((
            "vec_hash",
            serde_json::Value::String(header.vec_hash.clone()),
        ));
        entries.push((
            "vec_dtype",
            serde_json::Value::String(header.vec_dtype.clone()),
        ));
        entries.push(("vec_dim", serde_json::Value::Number(header.vec_dim.into())));
        entries.push(("ts", serde_json::Value::String(header.ts.clone())));
        if !header.extra.is_empty() {
            let mut m = serde_json::Map::new();
            for (k, val) in &header.extra {
                m.insert(k.clone(), serde_json::Value::String(val.clone()));
            }
            entries.push(("extra", serde_json::Value::Object(m)));
        }
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let mut map = serde_json::Map::with_capacity(entries.len());
        for (k, v) in entries {
            map.insert(k.to_string(), v);
        }
        serde_json::to_vec(&serde_json::Value::Object(map))
            .expect("JSON serialization of well-formed map cannot fail")
    }

    /// Parse a v1 pin JSON string into a [`Pin`] under the looser v1
    /// rules: no strict NFC / control-char / ts enforcement.
    ///
    /// Used only by the opt-in [`LegacyV1Verifier`](crate::verifier::LegacyV1Verifier).
    pub fn parse_v1_pin(s: &str) -> Result<Pin, AttestationError> {
        if s.len() > MAX_PIN_JSON_BYTES {
            return Err(AttestationError::SizeLimit {
                limit: MAX_PIN_JSON_BYTES,
                got: s.len(),
            });
        }
        let value: serde_json::Value = serde_json::from_str(s).map_err(AttestationError::Json)?;
        parse_v1_value(value)
    }

    fn parse_v1_value(value: serde_json::Value) -> Result<Pin, AttestationError> {
        let obj = match value {
            serde_json::Value::Object(m) => m,
            _ => {
                return Err(AttestationError::InvalidField {
                    field: "(root)",
                    detail: "pin must be a JSON object".into(),
                })
            }
        };

        let v_raw = obj
            .get("v")
            .ok_or(AttestationError::MissingField("v"))?
            .as_u64()
            .ok_or(AttestationError::InvalidField {
                field: "v",
                detail: "must be an unsigned integer".into(),
            })?;
        let v = v_raw as u32;
        if v != V1_PROTOCOL_VERSION {
            return Err(AttestationError::UnsupportedVersion {
                got: v,
                expected: V1_PROTOCOL_VERSION,
            });
        }

        // v1: minimal validation. Pull each field by name, accept what's there.
        let model = obj
            .get("model")
            .and_then(|x| x.as_str())
            .ok_or(AttestationError::MissingField("model"))?
            .to_owned();
        let kid = obj
            .get("kid")
            .and_then(|x| x.as_str())
            .ok_or(AttestationError::MissingField("kid"))?
            .to_owned();
        let source_hash = obj
            .get("source_hash")
            .and_then(|x| x.as_str())
            .ok_or(AttestationError::MissingField("source_hash"))?
            .to_owned();
        let vec_hash = obj
            .get("vec_hash")
            .and_then(|x| x.as_str())
            .ok_or(AttestationError::MissingField("vec_hash"))?
            .to_owned();
        let vec_dtype = obj
            .get("vec_dtype")
            .and_then(|x| x.as_str())
            .ok_or(AttestationError::MissingField("vec_dtype"))?
            .to_owned();
        let vec_dim = obj
            .get("vec_dim")
            .and_then(|x| x.as_u64())
            .ok_or(AttestationError::MissingField("vec_dim"))? as u32;
        let ts = obj
            .get("ts")
            .and_then(|x| x.as_str())
            .ok_or(AttestationError::MissingField("ts"))?
            .to_owned();
        let model_hash = obj
            .get("model_hash")
            .and_then(|x| x.as_str())
            .map(String::from);

        let extra: BTreeMap<String, String> = obj
            .get("extra")
            .and_then(|x| x.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                    .collect()
            })
            .unwrap_or_default();

        let sig_str = obj
            .get("sig")
            .and_then(|x| x.as_str())
            .ok_or(AttestationError::MissingField("sig"))?;
        let sig = b64url_decode(sig_str)?;
        if sig.len() != SIG_LEN {
            return Err(AttestationError::InvalidField {
                field: "sig",
                detail: format!("must decode to exactly {SIG_LEN} bytes; got {}", sig.len()),
            });
        }

        Ok(Pin {
            header: PinHeader {
                v,
                kid,
                model,
                model_hash,
                source_hash,
                vec_hash,
                vec_dtype,
                vec_dim,
                ts,
                extra,
            },
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> PinHeader {
        PinHeader {
            v: PROTOCOL_VERSION,
            kid: "k1".into(),
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
    fn domain_tag_is_13_bytes() {
        assert_eq!(DOMAIN_TAG.len(), 13);
        assert_eq!(DOMAIN_TAG, b"vectorpin/v2\x00");
    }

    #[test]
    fn canonicalize_starts_with_domain_tag() {
        let c = header().canonicalize();
        assert!(c.starts_with(DOMAIN_TAG));
    }

    #[test]
    fn canonicalize_includes_kid() {
        let body = String::from_utf8(header().canonicalize()[DOMAIN_TAG.len()..].to_vec()).unwrap();
        assert!(body.contains("\"kid\":\"k1\""));
    }

    #[test]
    fn canonicalize_is_deterministic() {
        let h = header();
        assert_eq!(h.canonicalize(), h.canonicalize());
    }
}
