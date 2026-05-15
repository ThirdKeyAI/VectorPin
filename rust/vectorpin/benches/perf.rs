// Copyright 2025 Jascha Wanger / Tarnover, LLC
// SPDX-License-Identifier: Apache-2.0

//! Per-operation microbenchmarks.
//!
//! Sweeps the four core operations (`hash_text`, `hash_vector`, `pin`,
//! `verify_full`) across representative input sizes:
//!
//! * vector dim ∈ {384, 768, 1024, 3072} — covers small open models
//!   through `text-embedding-3-large`.
//! * text length ∈ {128, 1024, 8192} chars — covers a short query, a
//!   typical RAG chunk, and a large chunk.
//!
//! Run with `cargo bench --bench perf`. Criterion writes a report to
//! `target/criterion/`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use vectorpin::hash::VectorRef;
use vectorpin::{hash_text, hash_vector, Signer, VecDtype, Verifier};

const VECTOR_DIMS: &[usize] = &[384, 768, 1024, 3072];
const TEXT_LENS: &[usize] = &[128, 1024, 8192];

fn make_vector(d: usize) -> Vec<f32> {
    (0..d).map(|i| (i as f32) * 0.001).collect()
}

fn make_text(n: usize) -> String {
    let pattern = "The quick brown fox jumps over the lazy dog. ";
    let mut s = String::with_capacity(n + pattern.len());
    while s.len() < n {
        s.push_str(pattern);
    }
    s.truncate(n);
    s
}

fn bench_hash_text(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_text");
    for &n in TEXT_LENS {
        let text = make_text(n);
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &text, |b, t| {
            b.iter(|| hash_text(black_box(t)))
        });
    }
    group.finish();
}

fn bench_hash_vector(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_vector");
    for &d in VECTOR_DIMS {
        let v = make_vector(d);
        group.throughput(Throughput::Bytes((d * 4) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(d), &v, |b, vv| {
            b.iter(|| hash_vector(VectorRef::F32(black_box(vv)), VecDtype::F32))
        });
    }
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign");
    let signer = Signer::generate("bench".into()).expect("test signer generate");
    let text = make_text(1024);
    for &d in VECTOR_DIMS {
        let v = make_vector(d);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(d), &v, |b, vv| {
            b.iter(|| {
                signer
                    .pin(
                        black_box(text.as_str()),
                        black_box("text-embedding-3-large"),
                        black_box(vv.as_slice()),
                    )
                    .expect("pin")
            })
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_full");
    let signer = Signer::generate("bench".into()).expect("test signer generate");
    let mut verifier = Verifier::new();
    verifier
        .add_key(signer.key_id(), signer.public_key_bytes())
        .unwrap();
    let text = make_text(1024);
    for &d in VECTOR_DIMS {
        let v = make_vector(d);
        let pin = signer
            .pin(text.as_str(), "text-embedding-3-large", v.as_slice())
            .expect("pin");
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(d), &v, |b, vv| {
            b.iter(|| {
                verifier
                    .verify_full(
                        black_box(&pin),
                        Some(black_box(text.as_str())),
                        Some(black_box(vv.as_slice())),
                        None,
                    )
                    .expect("verify")
            })
        });
    }
    group.finish();
}

fn bench_verify_signature_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_signature_only");
    let signer = Signer::generate("bench".into()).expect("test signer generate");
    let mut verifier = Verifier::new();
    verifier
        .add_key(signer.key_id(), signer.public_key_bytes())
        .unwrap();
    let text = make_text(1024);
    // Signature-only verification cost is independent of the vector
    // body — the dim doesn't enter the canonical header until vector
    // hashing — so we only measure one dim and report the steady state.
    let v = make_vector(3072);
    let pin = signer
        .pin(text.as_str(), "text-embedding-3-large", v.as_slice())
        .expect("pin");
    group.throughput(Throughput::Elements(1));
    group.bench_function("ed25519", |b| {
        b.iter(|| verifier.verify_signature(black_box(&pin)).expect("verify"))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_hash_text,
    bench_hash_vector,
    bench_sign,
    bench_verify,
    bench_verify_signature_only
);
criterion_main!(benches);
