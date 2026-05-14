// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Mirror of `examples/basic_usage.py` — runs the same four scenarios.

use vectorpin::{Pin, Signer, Verifier};

fn main() {
    let embedding: Vec<f32> = (0..128).map(|i| (i as f32) * 0.01).collect();
    let source = "The quick brown fox jumps over the lazy dog.";

    let signer = Signer::generate("demo-2026-05".to_string()).expect("non-empty kid");
    let pin = signer
        .pin(source, "text-embedding-3-large", embedding.as_slice())
        .expect("pin creation");

    println!("Pin JSON (this is what you'd store in your vector DB metadata):");
    println!("{}", pin.to_json());
    println!();

    let mut verifier = Verifier::new();
    verifier
        .add_key(signer.key_id(), signer.public_key_bytes())
        .expect("valid public key");

    // 1. honest verify
    let r = verifier.verify_full::<&[f32]>(&pin, Some(source), Some(embedding.as_slice()), None);
    println!("1. honest verify              -> {:?}", r);

    // 2. tampered vector
    let mut tampered = embedding.clone();
    tampered[0] += 1e-5;
    let r = verifier.verify_full::<&[f32]>(&pin, Some(source), Some(tampered.as_slice()), None);
    println!("2. tampered vector            -> {:?}", r);

    // 3. wrong source
    let r = verifier.verify_full::<&[f32]>(
        &pin,
        Some("different text"),
        Some(embedding.as_slice()),
        None,
    );
    println!("3. wrong source text          -> {:?}", r);

    // 4. wrong signing key (rogue signer with same kid as legit)
    let rogue = Signer::generate("demo-2026-05".to_string()).expect("non-empty kid");
    let rogue_pin = rogue
        .pin(source, "m", embedding.as_slice())
        .expect("rogue pin");
    let r = verifier.verify_signature(&rogue_pin);
    println!("4. forged with wrong key      -> {:?}", r);

    let restored = Pin::from_json(&pin.to_json()).expect("round trip");
    assert_eq!(restored, pin);
    println!("\nPin round-trip via JSON: OK");
}
