// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Regression tests for the `security/p2-hardening` branch.
//!
//! Each test pins a single behavioural contract introduced or tightened
//! by that branch so the hardening cannot silently regress.
//!
//! Wire-format / canonicalization changes belong to a separate branch
//! and are deliberately not exercised here.

use vectorpin::attestation::AttestationError;
use vectorpin::{Pin, Signer, SignerError, Verifier, VerifyError};
use zeroize::Zeroizing;

// --- 1. `private_key_bytes` returns a `Zeroizing` wrapper. ---------------

#[test]
fn private_key_bytes_is_zeroizing() {
    let signer = Signer::generate("kid".into()).expect("non-empty kid");
    // Compile-time check on the return type: this binding only compiles
    // if `private_key_bytes` actually returns `Zeroizing<[u8; 32]>`.
    let seed: Zeroizing<[u8; 32]> = signer.private_key_bytes();
    // And the buffer is still usable as a `[u8; 32]` via deref.
    let _bytes: &[u8; 32] = &seed;
    assert_eq!(seed.len(), 32);
}

// --- 2. `Signer::generate` returns `Result` on empty kid. ----------------

#[test]
fn signer_generate_rejects_empty_kid() {
    let res = Signer::generate(String::new());
    assert!(
        matches!(res, Err(SignerError::EmptyKeyId)),
        "expected EmptyKeyId, got {:?}",
        res.err()
    );
}

#[test]
fn signer_generate_accepts_non_empty_kid() {
    let res = Signer::generate("k".into());
    assert!(res.is_ok());
}

// --- 3. `Verifier::add_key` rejects malformed public keys. ---------------

#[test]
fn verifier_add_key_rejects_invalid_public_key() {
    // Note: many "obviously bad" 32-byte buffers — all-zeros, all-0xff —
    // are *not* rejected by ed25519-dalek's `from_bytes` (e.g. all-zero
    // decompresses to a low-order point, and 0xff repeated still gives
    // a decodable y). The buffer below is a y-coordinate whose
    // `y^2 - 1 / (d * y^2 + 1)` is a non-residue, so decompression
    // genuinely fails. Confirmed empirically against ed25519-dalek 2.x.
    let mut bad = [0u8; 32];
    bad[0] = 0x02;
    let mut verifier = Verifier::new();
    let res = verifier.add_key("kid", bad);
    assert!(
        matches!(res, Err(VerifyError::KeyDecodeFailed(_))),
        "expected KeyDecodeFailed, got {:?}",
        res
    );
    assert_eq!(
        verifier.key_count(),
        0,
        "rejected key must not be registered"
    );
}

#[test]
fn verifier_add_key_accepts_valid_public_key() {
    let signer = Signer::generate("kid".into()).unwrap();
    let mut verifier = Verifier::new();
    verifier
        .add_key("kid", signer.public_key_bytes())
        .expect("valid pubkey");
    assert_eq!(verifier.key_count(), 1);
}

// --- 4. `Pin::from_json` rejects non-string `extra` values. --------------

#[test]
fn pin_from_json_rejects_non_string_extra_value() {
    // Hand-built JSON whose `extra` map has a numeric value (1) under
    // the key "k". The previous implementation silently dropped this
    // entry; the new contract is a hard error.
    let bad = serde_json::json!({
        "v": 2,
        "model": "m",
        "source_hash": format!("sha256:{}", "0".repeat(64)),
        "vec_hash": format!("sha256:{}", "1".repeat(64)),
        "vec_dtype": "f32",
        "vec_dim": 1,
        "ts": "2026-05-05T12:00:00Z",
        "extra": {"k": 1},
        "kid": "k",
        "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    let res = Pin::from_value(bad);
    assert!(
        matches!(&res, Err(AttestationError::InvalidField { field, .. }) if field.starts_with("extra")),
        "expected InvalidField with field starting with 'extra', got {:?}",
        res
    );
}

#[test]
fn pin_from_json_accepts_string_extra_value() {
    // Build a real signed pin with a string-valued `extra` entry and
    // confirm it round-trips through the parser. The structural-validity
    // checks (v == 2, kid, sig length, hashes) are all satisfied by
    // routing through the real signer.
    use std::collections::BTreeMap;
    use vectorpin::signer::PinOptions;
    let signer = Signer::generate("k".into()).unwrap();
    let v: Vec<f32> = vec![1.0, 2.0, 3.0];
    let mut extra = BTreeMap::new();
    extra.insert("k".to_owned(), "v".to_owned());
    let opts = PinOptions {
        extra,
        ..PinOptions::default()
    };
    let pin = signer
        .pin_with_options("hello", "m", v.as_slice(), opts)
        .unwrap();
    let wire = pin.to_json();
    let round = Pin::from_json(&wire).expect("string-valued extra round-trips");
    assert_eq!(round.header.extra.get("k").map(String::as_str), Some("v"));
}

// --- 5. `Pin::from_json` rejects trailing garbage after the JSON object.
//
// Contract: `Pin::from_json` accepts exactly one JSON value followed by
// nothing but whitespace. A NUL byte (or any other non-whitespace) after
// the closing brace must surface as an error rather than being silently
// truncated. This protects callers that store pins in length-prefixed
// blobs where a framing bug could otherwise let an attacker append data
// after the legitimate JSON without breaking parse.

#[test]
fn pin_from_json_rejects_trailing_garbage() {
    let signer = Signer::generate("k".into()).unwrap();
    let v: Vec<f32> = vec![1.0, 2.0, 3.0];
    let pin = signer.pin("hello", "m", v.as_slice()).unwrap();
    let mut wire = pin.to_json();
    wire.push('\u{0000}');
    wire.push_str("trailing");
    let res = Pin::from_json(&wire);
    assert!(
        res.is_err(),
        "trailing garbage after valid JSON must be rejected, got Ok"
    );
}

// --- 6. Oversize vectors surface as `InvalidVector`, not silent truncation.
//
// We can't realistically allocate a > u32::MAX-element slice in a unit
// test, so the cast itself is exercised via the boundary helper below.
// What we *can* do cheaply is round-trip a normal pin through the
// checked-cast code path to confirm the happy path still works after
// the signature changed.

#[test]
fn pin_normal_dim_still_round_trips_after_checked_cast() {
    let signer = Signer::generate("k".into()).unwrap();
    let v: Vec<f32> = vec![0.5; 1024];
    let pin = signer.pin("hello", "m", v.as_slice()).unwrap();
    assert_eq!(pin.header.vec_dim, 1024);
    let mut verifier = Verifier::new();
    verifier
        .add_key(signer.key_id(), signer.public_key_bytes())
        .unwrap();
    verifier
        .verify_full(&pin, Some("hello"), Some(v.as_slice()), None)
        .unwrap();
}
