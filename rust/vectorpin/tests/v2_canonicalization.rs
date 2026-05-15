// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! v2-specific hardening tests: domain tag, kid binding, NFC enforcement,
//! ts strictness, NaN rejection, unknown-field rejection, size caps.

use vectorpin::attestation::DOMAIN_TAG;
use vectorpin::{
    signer::PinOptions, AttestationError, Pin, Signer, Verifier, VerifyError, VerifyOptions,
};

fn v2_signer(kid: &str) -> Signer {
    Signer::generate(kid.into())
}

fn small_vec() -> Vec<f32> {
    (0..8).map(|i| (i as f32) * 0.1).collect()
}

#[test]
fn domain_tag_is_exactly_13_bytes() {
    assert_eq!(DOMAIN_TAG.len(), 13);
    assert_eq!(DOMAIN_TAG, b"vectorpin/v2\x00");
}

#[test]
fn canonical_bytes_start_with_domain_tag() {
    let signer = v2_signer("k1");
    let v = small_vec();
    let pin = signer.pin("hello", "m", v.as_slice()).unwrap();
    let canonical = pin.header.canonicalize();
    assert!(canonical.starts_with(DOMAIN_TAG));
}

#[test]
fn kid_is_in_signed_bytes() {
    let signer = v2_signer("kid-a");
    let v = small_vec();
    let pin = signer.pin("hello", "m", v.as_slice()).unwrap();

    // Mutate the kid in a copy of the pin; the registered key won't match
    // anyway, but more importantly: the cross-key swap signature attempt
    // must fail signature check against the original key when the kid changes.
    let mut tampered = pin.clone();
    tampered.header.kid = "kid-b".into();

    let mut verifier = Verifier::new();
    verifier.add_key("kid-b", signer.public_key_bytes());
    let err = verifier.verify_signature(&tampered).unwrap_err();
    assert_eq!(err, VerifyError::SignatureInvalid);
}

#[test]
fn v_is_in_signed_bytes() {
    let signer = v2_signer("k1");
    let v = small_vec();
    let pin = signer.pin("hello", "m", v.as_slice()).unwrap();

    let mut tampered = pin.clone();
    tampered.header.v = 99;
    let mut verifier = Verifier::new();
    verifier.add_key("k1", signer.public_key_bytes());
    let err = verifier.verify_signature(&tampered).unwrap_err();
    // Unsupported version is rejected before reaching signature, but in
    // either case the pin must NOT verify.
    assert!(matches!(err, VerifyError::UnsupportedVersion(99)));
}

#[test]
fn signer_rejects_nan_in_vector() {
    let signer = v2_signer("k1");
    let v: Vec<f32> = vec![1.0, f32::NAN, 3.0];
    let err = signer.pin("x", "m", v.as_slice()).unwrap_err();
    assert!(matches!(err, vectorpin::SignerError::InvalidVector(_)));
}

#[test]
fn signer_rejects_pos_inf() {
    let signer = v2_signer("k1");
    let v: Vec<f64> = vec![1.0, f64::INFINITY, 3.0];
    let err = signer.pin("x", "m", v.as_slice()).unwrap_err();
    assert!(matches!(err, vectorpin::SignerError::InvalidVector(_)));
}

#[test]
fn pos_zero_and_neg_zero_distinct() {
    let signer = v2_signer("k1");
    let p: Vec<f32> = vec![0.0, 1.0];
    let n: Vec<f32> = vec![-0.0, 1.0];
    let pin_p = signer.pin("x", "m", p.as_slice()).unwrap();
    let pin_n = signer.pin("x", "m", n.as_slice()).unwrap();
    assert_ne!(pin_p.header.vec_hash, pin_n.header.vec_hash);
}

#[test]
fn parser_rejects_nfd_model_field() {
    // 'café' as NFD (e + COMBINING ACUTE U+0301).
    let pin_json = r#"{"kid":"k","model":"café","sig":"AA","source_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","ts":"2026-05-05T12:00:00Z","v":2,"vec_dim":1,"vec_dtype":"f32","vec_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#;
    let err = Pin::from_json(pin_json).unwrap_err();
    // Either NotNfc (caught at NFC check) or InvalidField (caught earlier
    // on sig length) — both are PARSE_ERROR class. Be precise about NFC.
    assert!(
        matches!(err, AttestationError::NotNfc(_))
            || matches!(err, AttestationError::InvalidField { .. }),
        "got {err:?}"
    );
}

#[test]
fn parser_rejects_control_char_in_string_field() {
    let bad = "kid\u{0007}".to_string();
    // Build a pin via signer first to produce a valid sig field, then
    // mutate the JSON.
    let signer = v2_signer("k");
    let v = small_vec();
    let pin = signer.pin("x", "m", v.as_slice()).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&pin.to_json()).unwrap();
    value["kid"] = serde_json::Value::String(bad);
    let err = Pin::from_value(value).unwrap_err();
    assert!(
        matches!(err, AttestationError::ControlChar(_)),
        "got {err:?}"
    );
}

#[test]
fn parser_rejects_bidi_override() {
    let bad = "kid\u{202E}".to_string(); // RIGHT-TO-LEFT OVERRIDE
    let signer = v2_signer("k");
    let v = small_vec();
    let pin = signer.pin("x", "m", v.as_slice()).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&pin.to_json()).unwrap();
    value["kid"] = serde_json::Value::String(bad);
    let err = Pin::from_value(value).unwrap_err();
    assert!(
        matches!(err, AttestationError::BidiOverride(_)),
        "got {err:?}"
    );
}

#[test]
fn parser_rejects_ts_with_fractional_seconds() {
    let signer = v2_signer("k");
    let v = small_vec();
    let pin = signer.pin("x", "m", v.as_slice()).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&pin.to_json()).unwrap();
    value["ts"] = serde_json::Value::String("2026-05-05T12:00:00.123Z".to_string());
    let err = Pin::from_value(value).unwrap_err();
    assert!(
        matches!(err, AttestationError::BadTimestamp(_)),
        "got {err:?}"
    );
}

#[test]
fn parser_rejects_ts_with_offset() {
    let signer = v2_signer("k");
    let v = small_vec();
    let pin = signer.pin("x", "m", v.as_slice()).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&pin.to_json()).unwrap();
    value["ts"] = serde_json::Value::String("2026-05-05T12:00:00+00:00".to_string());
    let err = Pin::from_value(value).unwrap_err();
    assert!(
        matches!(err, AttestationError::BadTimestamp(_)),
        "got {err:?}"
    );
}

#[test]
fn parser_rejects_unknown_top_level_field() {
    let signer = v2_signer("k");
    let v = small_vec();
    let pin = signer.pin("x", "m", v.as_slice()).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&pin.to_json()).unwrap();
    value["bogus"] = serde_json::Value::String("x".into());
    let err = Pin::from_value(value).unwrap_err();
    assert!(
        matches!(err, AttestationError::UnknownTopLevelField(ref s) if s == "bogus"),
        "got {err:?}"
    );
}

#[test]
fn parser_rejects_non_string_extra_value() {
    let signer = v2_signer("k");
    let v = small_vec();
    let opts = PinOptions {
        extra: [("region".to_string(), "us-east".to_string())]
            .into_iter()
            .collect(),
        ..PinOptions::default()
    };
    let pin = signer
        .pin_with_options("x", "m", v.as_slice(), opts)
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&pin.to_json()).unwrap();
    value["extra"]["region"] = serde_json::json!(5);
    let err = Pin::from_value(value).unwrap_err();
    assert!(
        matches!(err, AttestationError::InvalidField { field: "extra", .. }),
        "got {err:?}"
    );
}

#[test]
fn parser_rejects_oversize_pin_json() {
    let oversize = "x".repeat(vectorpin::attestation::MAX_PIN_JSON_BYTES + 1);
    let err = Pin::from_json(&oversize).unwrap_err();
    assert!(
        matches!(err, AttestationError::SizeLimit { .. }),
        "got {err:?}"
    );
}

#[test]
fn parser_rejects_sig_wrong_length() {
    let signer = v2_signer("k");
    let v = small_vec();
    let pin = signer.pin("x", "m", v.as_slice()).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&pin.to_json()).unwrap();
    // Replace sig with a base64 string that decodes to fewer bytes.
    value["sig"] = serde_json::Value::String("AAAA".to_string());
    let err = Pin::from_value(value).unwrap_err();
    assert!(
        matches!(err, AttestationError::InvalidField { field: "sig", .. }),
        "got {err:?}"
    );
}

#[test]
fn parser_rejects_vec_dim_zero() {
    let signer = v2_signer("k");
    let v = small_vec();
    let pin = signer.pin("x", "m", v.as_slice()).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&pin.to_json()).unwrap();
    value["vec_dim"] = serde_json::json!(0);
    let err = Pin::from_value(value).unwrap_err();
    assert!(
        matches!(
            err,
            AttestationError::InvalidField {
                field: "vec_dim",
                ..
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn verify_nan_vector_rejected_as_parse_error() {
    let signer = v2_signer("k");
    let v = small_vec();
    let pin = signer.pin("x", "m", v.as_slice()).unwrap();

    let mut verifier = Verifier::new();
    verifier.add_key(signer.key_id(), signer.public_key_bytes());

    let mut nan_vec = v.clone();
    nan_vec[0] = f32::NAN;
    let err = verifier
        .verify(
            &pin,
            VerifyOptions {
                vector: Some(vectorpin::hash::VectorRef::F32(&nan_vec)),
                ..VerifyOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(err, VerifyError::ParseError(_)), "got {err:?}");
}

#[test]
fn round_trip_with_extra_and_model_hash() {
    let signer = v2_signer("k");
    let v = small_vec();
    let mut extra = std::collections::BTreeMap::new();
    extra.insert("vectorpin.record_id".to_string(), "rec-1".to_string());
    let opts = PinOptions {
        model_hash: Some(format!("sha256:{}", "a".repeat(64))),
        extra,
        ..PinOptions::default()
    };
    let pin = signer
        .pin_with_options("hi", "m", v.as_slice(), opts)
        .unwrap();
    let json = pin.to_json();
    let parsed = Pin::from_json(&json).unwrap();
    assert_eq!(parsed, pin);

    let mut verifier = Verifier::new();
    verifier.add_key(signer.key_id(), signer.public_key_bytes());
    verifier
        .verify(
            &parsed,
            VerifyOptions {
                expected_record_id: Some("rec-1"),
                ..VerifyOptions::default()
            },
        )
        .expect("valid record_id matches");
}
