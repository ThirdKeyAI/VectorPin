// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Opt-in legacy v1 verifier tests.
//!
//! Confirms that `LegacyV1Verifier` accepts every entry in
//! `testvectors/v1.json` (the original v1 fixtures) without modification,
//! while the default v2 verifier rejects them with UNSUPPORTED_VERSION.

use std::path::PathBuf;

use base64::Engine;
use serde::Deserialize;

use vectorpin::{KeyEntry, LegacyV1Verifier, Pin, Verifier, VerifyError, VerifyOptions};

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .expect("base64 fixture")
}

fn v1_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("testvectors")
        .join("v1.json")
}

#[derive(Debug, Deserialize)]
struct V1Bundle {
    public_key_b64: String,
    key_id: String,
    fixtures: Vec<V1Fixture>,
}

#[derive(Debug, Deserialize)]
struct V1Fixture {
    name: String,
    expected: V1Expected,
}

#[derive(Debug, Deserialize)]
struct V1Expected {
    pin_json: String,
}

#[test]
fn legacy_verifier_accepts_v1_fixtures() {
    let raw = std::fs::read_to_string(v1_path()).expect("read v1.json");
    let bundle: V1Bundle = serde_json::from_str(&raw).expect("parse v1.json");

    let pk: [u8; 32] = b64(&bundle.public_key_b64)
        .try_into()
        .expect("public key 32 bytes");
    let mut verifier = LegacyV1Verifier::new();
    verifier.add_key_entry(&bundle.key_id, KeyEntry::from_public_bytes(pk).unwrap());

    assert!(!bundle.fixtures.is_empty());
    for fx in &bundle.fixtures {
        eprintln!("legacy v1 fixture: {}", fx.name);
        let pin = LegacyV1Verifier::parse_pin(&fx.expected.pin_json).expect("parse v1");
        verifier
            .verify(&pin, VerifyOptions::default())
            .expect("legacy verifier accepts v1");
    }
}

#[test]
fn default_v2_verifier_rejects_v1_fixtures() {
    let raw = std::fs::read_to_string(v1_path()).expect("read v1.json");
    let bundle: V1Bundle = serde_json::from_str(&raw).expect("parse v1.json");

    // Strict v2 verifier must NOT accept v1 — confirms wire-format break.
    let mut verifier = Verifier::new();
    verifier
        .add_key(
            &bundle.key_id,
            b64(&bundle.public_key_b64).try_into().unwrap(),
        )
        .unwrap();

    for fx in &bundle.fixtures {
        // The strict parser rejects v1 pins outright, before reaching
        // the verifier. That maps to a PARSE_ERROR for the caller.
        match Pin::from_json(&fx.expected.pin_json) {
            Ok(pin) => {
                let err = verifier
                    .verify(&pin, VerifyOptions::default())
                    .expect_err("v2 verifier must reject v1 pins");
                assert!(matches!(err, VerifyError::UnsupportedVersion(1)));
            }
            Err(e) => {
                // Strict v2 parser rejects pins whose `v != 2`.
                let msg = format!("{e:?}");
                assert!(
                    msg.contains("UnsupportedVersion")
                        || msg.contains("unsupported")
                        || msg.contains("got: 1"),
                    "unexpected parse error: {msg}"
                );
            }
        }
    }
}
