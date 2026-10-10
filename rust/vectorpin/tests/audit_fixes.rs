// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Regression tests for the security-review fixes.
//!
//! Each test names the finding it pins down and fails on the pre-fix
//! code: precision widening (VP-1), signer-chosen revocation clock
//! (VP-5), calendar validation and checked date arithmetic (VP-9),
//! `expected_model_hash` (VP-10), integer parsing parity (VP-13),
//! per-field byte caps (VP-14), plus VectorSmuggle-style perturbations
//! and property tests over the canonical byte encoding.

use std::collections::BTreeMap;

use proptest::prelude::*;
use vectorpin::attestation::{AttestationError, MAX_MODEL_BYTES};
use vectorpin::hash::{canonical_vector_bytes, VectorRef};
use vectorpin::signer::PinOptions;
use vectorpin::{
    parse_ts_unix, KeyEntry, LegacyV1Verifier, Pin, Signer, VecDtype, Verifier, VerifyError,
    VerifyOptions,
};

fn world() -> (Signer, Verifier) {
    let signer = Signer::generate("k".into()).unwrap();
    let mut verifier = Verifier::new();
    verifier
        .add_key(signer.key_id(), signer.public_key_bytes())
        .unwrap();
    (signer, verifier)
}

fn f64_vector(dim: usize) -> Vec<f64> {
    // Deterministic pseudo-random values in (-1, 1).
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..dim)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ((x >> 11) as f64 / (1u64 << 53) as f64) * 2.0 - 1.0
        })
        .collect()
}

/// Rewrite the low 28 mantissa bits of every element with a non-zero
/// payload, leaving each element's f32 rounding unchanged.
fn hide_payload_in_low_bits(v: &[f64]) -> Vec<f64> {
    let mut seed: u64 = 42;
    let out: Vec<f64> = v
        .iter()
        .map(|&x| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let payload = (seed >> 36) & ((1 << 28) - 1);
            let payload = if payload == 0 { 1 } else { payload };
            let bits = (x.to_bits() & !((1u64 << 28) - 1)) | payload;
            f64::from_bits(bits)
        })
        .collect();
    for (a, b) in v.iter().zip(&out) {
        assert_eq!(*a as f32, *b as f32, "f32 rounding must be preserved");
    }
    assert_ne!(v, out.as_slice());
    out
}

fn opts_vec(v: VectorRef<'_>) -> VerifyOptions<'_> {
    VerifyOptions {
        vector: Some(v),
        ..VerifyOptions::default()
    }
}

// ---- VP-1 ------------------------------------------------------------------

#[test]
fn f64_low_bit_channel_is_rejected_against_f32_pin() {
    let (signer, verifier) = world();
    let v64 = f64_vector(3072);
    let pin = signer
        .pin_with_options(
            "s",
            "m",
            v64.as_slice(),
            PinOptions {
                dtype: Some(VecDtype::F32),
                ..PinOptions::default()
            },
        )
        .unwrap();
    assert_eq!(pin.header.vec_dtype, "f32");
    let smuggled = hide_payload_in_low_bits(&v64);
    let err = verifier
        .verify(&pin, opts_vec(VectorRef::F64(&smuggled)))
        .unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::PrecisionWidening {
                supplied: VecDtype::F64,
                pinned: VecDtype::F32
            }
        ),
        "got {err:?}"
    );
    // Even the untouched f64 input is refused: the verifier cannot know
    // which low-order bits the store may have changed.
    let err = verifier
        .verify(&pin, opts_vec(VectorRef::F64(&v64)))
        .unwrap_err();
    assert!(matches!(err, VerifyError::PrecisionWidening { .. }));
    // The f32 representation (what an f32 store persists) passes.
    let v32: Vec<f32> = v64.iter().map(|&x| x as f32).collect();
    verifier
        .verify(&pin, opts_vec(VectorRef::F32(&v32)))
        .expect("stored f32 verifies");
}

#[test]
fn f64_pin_catches_low_bit_modification() {
    let (signer, verifier) = world();
    let v64 = f64_vector(512);
    let pin = signer.pin("s", "m", v64.as_slice()).unwrap();
    assert_eq!(pin.header.vec_dtype, "f64");
    let err = verifier
        .verify(
            &pin,
            opts_vec(VectorRef::F64(&hide_payload_in_low_bits(&v64))),
        )
        .unwrap_err();
    assert_eq!(err, VerifyError::VectorTampered);
}

#[test]
fn narrower_than_pinned_is_allowed() {
    let (signer, verifier) = world();
    let v32: Vec<f32> = vec![0.1, 0.2, 0.3];
    let pin = signer
        .pin_with_options(
            "s",
            "m",
            v32.as_slice(),
            PinOptions {
                dtype: Some(VecDtype::F64),
                ..PinOptions::default()
            },
        )
        .unwrap();
    verifier
        .verify(&pin, opts_vec(VectorRef::F32(&v32)))
        .expect("f32 slice widens exactly to an f64 pin");
}

#[test]
fn precision_widening_displays_both_dtypes() {
    let err = VerifyError::PrecisionWidening {
        supplied: VecDtype::F64,
        pinned: VecDtype::F32,
    };
    let msg = err.to_string();
    assert!(msg.contains("f64") && msg.contains("f32"), "{msg}");
}

// ---- VP-5 ------------------------------------------------------------------

#[test]
fn backdated_forgery_rejected_with_trusted_time() {
    let signer = Signer::generate("k".into()).unwrap();
    let compromise = parse_ts_unix("2026-06-01T00:00:00Z").unwrap();
    let mut verifier = Verifier::new();
    verifier.add_key_entry(
        signer.key_id(),
        KeyEntry::from_public_bytes(signer.public_key_bytes())
            .unwrap()
            .with_valid_until(compromise),
    );
    let v: Vec<f32> = vec![1.0, 2.0];
    let forged = signer
        .pin_with_options(
            "s",
            "m",
            v.as_slice(),
            PinOptions {
                timestamp: Some("2026-05-01T00:00:00Z".into()),
                ..PinOptions::default()
            },
        )
        .unwrap();
    // Without a trusted clock the backdated pin verifies (the limitation).
    verifier.verify_signature(&forged).unwrap();
    // Bound to the store's ingestion time, it is rejected.
    let ingested = parse_ts_unix("2026-07-01T00:00:00Z").unwrap();
    let err = verifier
        .verify(
            &forged,
            VerifyOptions {
                trusted_time: Some(ingested),
                ..VerifyOptions::default()
            },
        )
        .unwrap_err();
    assert_eq!(err, VerifyError::KeyExpired);
    // A pin whose ts postdates the trusted time is also rejected.
    let before = parse_ts_unix("2026-04-01T00:00:00Z").unwrap();
    let err = verifier
        .verify(
            &forged,
            VerifyOptions {
                trusted_time: Some(before),
                ..VerifyOptions::default()
            },
        )
        .unwrap_err();
    assert_eq!(err, VerifyError::KeyExpired);
    // Honest: ts before trusted time, both inside the window.
    let honest = parse_ts_unix("2026-05-02T00:00:00Z").unwrap();
    verifier
        .verify(
            &forged,
            VerifyOptions {
                trusted_time: Some(honest),
                ..VerifyOptions::default()
            },
        )
        .unwrap();
}

// ---- VP-9 ------------------------------------------------------------------

fn pin_json_with_ts(signer: &Signer, ts: &str) -> String {
    let v: Vec<f32> = vec![1.0];
    let pin = signer.pin("s", "m", v.as_slice()).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&pin.to_json()).unwrap();
    value["ts"] = serde_json::Value::String(ts.to_string());
    value.to_string()
}

#[test]
fn invalid_calendar_dates_rejected_at_parse() {
    let (signer, _) = world();
    for bad in [
        "2026-03-00T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-05-05T24:00:00Z",
    ] {
        let err = Pin::from_json(&pin_json_with_ts(&signer, bad)).unwrap_err();
        assert!(
            matches!(err, AttestationError::BadTimestamp(_)),
            "{bad}: {err:?}"
        );
    }
}

#[test]
fn hand_built_pin_with_day_zero_does_not_panic_in_window_check() {
    // `Pin` fields are public, so a caller can bypass the parser. The
    // verifier must still never underflow: day 0 of March used to reach
    // `(0 + 2) / 5 + 0 - 1` in u32 arithmetic.
    let signer = Signer::generate("k".into()).unwrap();
    let v: Vec<f32> = vec![1.0];
    let mut pin = signer.pin("s", "m", v.as_slice()).unwrap();
    pin.header.ts = "2026-03-00T00:00:00Z".into();
    let mut verifier = Verifier::new();
    verifier.add_key_entry(
        signer.key_id(),
        KeyEntry::from_public_bytes(signer.public_key_bytes())
            .unwrap()
            .with_valid_from(0),
    );
    let err = verifier.verify_signature(&pin).unwrap_err();
    assert_eq!(err, VerifyError::KeyExpired);
}

// ---- VP-10 -----------------------------------------------------------------

#[test]
fn expected_model_hash_is_enforced() {
    let (signer, verifier) = world();
    let v: Vec<f32> = vec![1.0, 2.0];
    let good = format!("sha256:{}", "a".repeat(64));
    let bad = format!("sha256:{}", "b".repeat(64));
    let pin = signer
        .pin_with_options(
            "s",
            "m",
            v.as_slice(),
            PinOptions {
                model_hash: Some(good.clone()),
                ..PinOptions::default()
            },
        )
        .unwrap();
    fn with(h: &str) -> VerifyOptions<'_> {
        VerifyOptions {
            expected_model_hash: Some(h),
            ..VerifyOptions::default()
        }
    }
    verifier.verify(&pin, with(&good)).unwrap();
    assert!(matches!(
        verifier.verify(&pin, with(&bad)).unwrap_err(),
        VerifyError::ModelMismatch { .. }
    ));
    let no_hash = signer.pin("s", "m", v.as_slice()).unwrap();
    assert!(matches!(
        verifier.verify(&no_hash, with(&good)).unwrap_err(),
        VerifyError::ModelMismatch { .. }
    ));
}

// ---- VP-13 -----------------------------------------------------------------

fn base_value(signer: &Signer) -> serde_json::Value {
    let v: Vec<f32> = vec![1.0];
    let pin = signer.pin("s", "m", v.as_slice()).unwrap();
    serde_json::from_str(&pin.to_json()).unwrap()
}

#[test]
fn v_above_u32_is_rejected_not_truncated() {
    let (signer, _) = world();
    let mut value = base_value(&signer);
    // 4294967298 as u32 == 2; the old parser accepted this as v=2.
    value["v"] = serde_json::json!(4_294_967_298u64);
    let err = Pin::from_value(value.clone()).unwrap_err();
    assert!(
        matches!(err, AttestationError::InvalidField { field: "v", .. }),
        "{err:?}"
    );
    let err = LegacyV1Verifier::parse_pin(&value.to_string()).unwrap_err();
    assert!(matches!(err, VerifyError::ParseError(_)), "{err:?}");
}

#[test]
fn non_integer_v_is_rejected() {
    let (signer, _) = world();
    let mut value = base_value(&signer);
    value["v"] = serde_json::json!(2.0);
    assert!(Pin::from_value(value).is_err());
}

#[test]
fn extra_null_is_rejected() {
    let (signer, _) = world();
    let mut value = base_value(&signer);
    value["extra"] = serde_json::Value::Null;
    let err = Pin::from_value(value).unwrap_err();
    assert!(
        matches!(err, AttestationError::InvalidField { field: "extra", .. }),
        "{err:?}"
    );
}

// ---- VP-14 -----------------------------------------------------------------

#[test]
fn oversize_model_rejected_on_value_path() {
    let (signer, _) = world();
    let mut value = base_value(&signer);
    value["model"] = serde_json::Value::String("x".repeat(MAX_MODEL_BYTES + 1));
    let err = Pin::from_value(value).unwrap_err();
    assert!(matches!(err, AttestationError::SizeLimit { .. }), "{err:?}");
}

#[test]
fn oversize_kid_rejected_on_value_path() {
    let (signer, _) = world();
    let mut value = base_value(&signer);
    value["kid"] = serde_json::Value::String("k".repeat(257));
    let err = Pin::from_value(value).unwrap_err();
    assert!(matches!(err, AttestationError::SizeLimit { .. }), "{err:?}");
}

// ---- VectorSmuggle-style perturbations ------------------------------------

#[test]
fn perturbations_are_detected() {
    let (signer, verifier) = world();
    let base: Vec<f32> = f64_vector(256).iter().map(|&x| x as f32).collect();
    let pin = signer.pin("s", "m", base.as_slice()).unwrap();
    let cases: Vec<(&str, Vec<f32>)> = vec![
        ("noise_1e-3", base.iter().map(|x| x + 1e-3).collect()),
        ("noise_1e-5", base.iter().map(|x| x + 1e-5).collect()),
        ("scaling", base.iter().map(|x| x * 1.0001).collect()),
        ("offset", base.iter().map(|x| x + 1e-4).collect()),
        ("lsb_flip_one", {
            let mut v = base.clone();
            v[0] = f32::from_bits(v[0].to_bits() ^ 1);
            v
        }),
        ("lsb_flip_all", {
            base.iter()
                .map(|x| f32::from_bits(x.to_bits() ^ 1))
                .collect()
        }),
        ("rotation_swap", {
            let mut v = base.clone();
            v.swap(0, 1);
            v
        }),
    ];
    for (name, perturbed) in cases {
        assert_ne!(perturbed, base, "{name}");
        let err = verifier
            .verify(&pin, opts_vec(VectorRef::F32(&perturbed)))
            .unwrap_err();
        assert_eq!(err, VerifyError::VectorTampered, "{name}");
    }
    verifier
        .verify(&pin, opts_vec(VectorRef::F32(&base)))
        .unwrap();
}

// ---- property tests --------------------------------------------------------

proptest! {
    #[test]
    fn f32_canonical_bytes_are_le_concatenation(v in proptest::collection::vec(any::<f32>(), 1..64)) {
        let v: Vec<f32> = v.into_iter().filter(|x| x.is_finite()).collect();
        prop_assume!(!v.is_empty());
        let expected: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
        prop_assert_eq!(canonical_vector_bytes(VectorRef::F32(&v), VecDtype::F32), expected);
    }

    #[test]
    fn f64_canonical_bytes_are_le_concatenation(v in proptest::collection::vec(any::<f64>(), 1..64)) {
        let v: Vec<f64> = v.into_iter().filter(|x| x.is_finite()).collect();
        prop_assume!(!v.is_empty());
        let expected: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
        prop_assert_eq!(canonical_vector_bytes(VectorRef::F64(&v), VecDtype::F64), expected);
    }

    #[test]
    fn f64_to_f32_cast_matches_as_f32(v in proptest::collection::vec(-1e30f64..1e30, 1..64)) {
        let expected: Vec<u8> = v.iter().flat_map(|x| (*x as f32).to_le_bytes()).collect();
        prop_assert_eq!(canonical_vector_bytes(VectorRef::F64(&v), VecDtype::F32), expected);
    }

    #[test]
    fn pin_round_trips_and_verifies(
        model in "[a-zA-Z0-9 _.-]{1,32}",
        source in ".{0,64}",
        v in proptest::collection::vec(-1e6f32..1e6, 1..16),
    ) {
        let (signer, verifier) = world();
        let mut extra = BTreeMap::new();
        extra.insert("vectorpin.record_id".to_string(), "r".to_string());
        let pin = signer
            .pin_with_options(&source, &model, v.as_slice(), PinOptions { extra, ..PinOptions::default() })
            .unwrap();
        let back = Pin::from_json(&pin.to_json()).unwrap();
        prop_assert_eq!(&back, &pin);
        verifier
            .verify(
                &back,
                VerifyOptions {
                    source: Some(&source),
                    vector: Some(VectorRef::F32(&v)),
                    expected_record_id: Some("r"),
                    ..VerifyOptions::default()
                },
            )
            .unwrap();
    }
}
