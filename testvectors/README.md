# VectorPin Cross-Language Test Vectors

These JSON fixtures lock down the wire format and signature behavior
of the VectorPin protocol. Every language implementation
(Python, Rust, TypeScript) consumes them in CI.

## Files

### Protocol v2 (current)

- `v2.json` — positive fixtures. Each has an input (source, model,
  vector bytes, dtype, dim, timestamp, optional model_hash / extra)
  and the produced pin JSON, expected canonical bytes (with the
  `vectorpin/v2\x00` domain tag prepended), and component hashes.
  Seven entries: small f32, small f64, pin with `model_hash`, pin with
  `extra` containing a `vectorpin.record_id` replay-protection key,
  f32 IEEE-754 edge cases (signed zeros, subnormals, max, 1 + ulp),
  f64 edge cases, and an f64 input pinned as f32 whose values are
  exact round-to-nearest-even ties. That last entry carries
  `input.vec_native_dtype: "f64"`: `vec_b64` holds the f64 input
  bytes, the signer casts at sign time, and consumers verify with the
  f32 cast (what an f32 store persists) — verifying with the f64 input
  itself is a SHAPE_MISMATCH under the §3.2 precision rule.

- `negative_v2.json` — negative fixtures covering every failure mode
  in spec §5: VECTOR_TAMPERED, SOURCE_MISMATCH, MODEL_MISMATCH (wrong
  model, wrong / missing model_hash), SIGNATURE_INVALID (bit-flip,
  vec_dim tamper), UNSUPPORTED_VERSION, UNKNOWN_KEY, KEY_EXPIRED
  (ts after valid_until; backdated ts caught by a trusted time),
  SHAPE_MISMATCH (truncated vector; f64 vector with low-bit
  perturbation against an f32 pin; f32-exact f64 vector against an
  f32 pin), PARSE_ERROR (wrong sig length, padded sig, non-canonical
  trailing bits, unknown top-level field, non-string extra,
  `extra: null`, `v: 2.0`, NaN at verify, NFD string, lone surrogate,
  malformed and calendar-invalid timestamps, oversize pin, kid / model
  over the field caps), RECORD_MISMATCH, COLLECTION_MISMATCH, and
  TENANT_MISMATCH. Each entry carries a `description` and an
  `expected_failure` code matching a v2 VerifyError enum value.

  Optional per-entry inputs consumers must honor: `tampered_vec_b64` /
  `nan_vec_b64` with `vec_dtype` (the dtype of the *supplied* bytes,
  which may be wider than the pin's) and `vec_dim`; `tampered_source`;
  `expected_model`; `expected_model_hash`; `expected_record_id` /
  `expected_collection_id` / `expected_tenant_id`; `key_valid_from` /
  `key_valid_until` (register the key with that window); and
  `trusted_time` (pass as the verifier-trusted instant).

### Protocol v1 (legacy)

- `v1.json` — positive fixtures from the v1 protocol. These verify
  ONLY under `vectorpin.LegacyV1Verifier` (the opt-in migration
  verifier). The strict v2 verifier rejects them as
  UNSUPPORTED_VERSION.

- `negative_v1.json` — one v1 negative fixture (tampered vector).
  Retained for migration regression testing.

These v1 files are frozen — do NOT regenerate them. The v1 wire
format is closed and the existing signatures must remain
byte-for-byte verifiable.

## Reproducing

The v2 signing key is deterministic:

- seed: `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`
  (bytes 0x00..0x1f in URL-safe base64, no padding)
- key id: `test-vectors-v2-2026-05`

The v1 fixtures used the same seed under key id
`test-vectors-2026-05`.

Re-running `scripts/generate_test_vectors.py` regenerates `v2.json`
and `negative_v2.json` byte-for-byte from the deterministic seed. If
your port disagrees, the canonicalization or signing algorithm is off.

The deterministic seed contract is load-bearing for cross-language
parity: every Rust/TypeScript test that consumes these fixtures
re-derives the signature from the same seed and compares against the
published bytes. Do not change the seed without coordinating with
every implementation and bumping the cross-language compat-test
expectations.

The seeds are published intentionally — these fixtures are public test
data, not production keys.

## Domain tag (v2)

v2 pins are signed over `DOMAIN_TAG || canonical_json(header)` where
`DOMAIN_TAG = b"vectorpin/v2\x00"` (13 bytes — 12 ASCII characters
"vectorpin/v2" plus one NUL terminator). Ports MUST match those exact
bytes. See `src/vectorpin/attestation.py` for the canonical constant.
