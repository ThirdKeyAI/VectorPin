# Changelog

All notable changes to VectorPin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-05-15

Promotes 0.2.0-rc.1 to a stable release with one additive change since
the release candidate: a new pgvector adapter and `audit-pgvector` CLI
command. No wire-format changes from rc.1; pins produced by rc.1
verify on 0.2.0 and vice-versa.

### Added

- `PgVectorAdapter` (`vectorpin.adapters.pgvector`) — reads and writes
  pins on a pgvector-equipped Postgres table. Same shape as
  `QdrantAdapter` / `LanceDBAdapter`: `iter_records`, `get`,
  `attach_pin`, classmethod `connect(dsn, table, *, id_column='id',
  vector_column='embedding', pin_column='vectorpin')`.
- `audit-pgvector` CLI subcommand mirroring `audit-{lancedb,chroma,
  qdrant}`.
- `vectorpin[pgvector]` optional extra (`psycopg[binary]>=3.1` +
  `pgvector>=0.3`).
- `scripts/pinecone_live_e2e.py` — self-contained manual verification
  script that creates a fresh Pinecone serverless index, runs the
  full sign-attach-verify round-trip via `PineconeAdapter`, exercises
  tamper rejection, and deletes the index on exit. Verified against
  live Pinecone (AWS us-east-1).
- 22 new tests (`tests/test_adapter_pgvector.py`): 14 offline TLS-guard
  / identifier-validation tests + 8 live integration tests that
  auto-discover the compose service via
  `VECTORPIN_TEST_PGVECTOR_URL` / `PGVECTOR_URL` env vars and skip
  cleanly otherwise.

### Hardening

- pgvector adapter applies the same security guards as the other
  remote-DB adapters: refuses plaintext postgres DSNs to non-loopback
  hosts without `sslmode=require` (or stronger), with the
  `VECTORPIN_ALLOW_INSECURE_HTTP=1` env-scoped escape hatch.
- SQL identifier validation (`^[A-Za-z_][A-Za-z0-9_]*$`) on every
  interpolated name (table, id column, vector column, pin column),
  matching the LanceDB adapter's contract. Postgres has no
  parameterized form for identifiers, so this is the only line of
  defense against shell-style injection in those parameters.

### Notes

The pgvector adapter accepts both JSONB and TEXT pin columns — JSONB
returns a decoded `dict` (parsed via `Pin.from_dict`), TEXT returns a
`str` (parsed via `Pin.from_json`). Both routes go through the strict
v2 schema validation.

## [0.2.0-rc.1] — 2026-05-14

Release candidate for 0.2.0. **This is a wire-format break.** Pins
produced by 0.1.x do not verify under the default 0.2.0 verifier;
a `LegacyV1Verifier` is shipped in all three languages as an opt-in
migration aid. The break is the response to a security audit
(2026-05) that identified four cross-implementation issues. See
[`docs/spec.md` §12](docs/spec.md#12-changes-from-v1) for the full
v1 → v2 change list.

### Protocol — wire-format v2

- Protocol version field bumped to `v: 2`. Strict v2 verifiers reject
  v1 pins.
- **`v` and `kid` are now signed.** Both are part of the canonical
  payload, defeating downgrade attacks and cross-key swap attacks.
- **Domain separator.** Signed bytes are now
  `b"vectorpin/v2\x00" || canonical_json(header)` (13-byte tag),
  preventing cross-protocol signature reuse with any sister Trust-Stack
  protocol.
- **NaN/Inf rejection at sign time.** `+0.0` and `-0.0` remain distinct.
- **NFC normalization mandatory** on every string-typed field
  (`model`, `kid`, `ts`, every `extra` key, every `extra` value).
  Control characters U+0000–U+001F and bidi overrides U+202A–U+202E /
  U+2066–U+2069 are rejected.
- **`extra` is strictly `map<string, string>`.** Non-string values
  cause `PARSE_ERROR`.
- **Strict timestamp format.** `ts` must match exactly
  `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`. No
  fractional seconds, no offset variants.
- **Unknown top-level fields rejected** at parse time.
- **Size limits enforced** (`docs/spec.md` §4.3): pin JSON ≤ 64 KiB,
  ≤ 32 `extra` entries, key ≤ 128 B, value ≤ 1 KiB, `vec_dim` ≤ 2^20,
  decoded `sig` length exactly 64.

### Verification — replay protection and revocation

- New `KeyEntry` registry shape with optional
  `(valid_from, valid_until)` window. Pins whose `ts` falls outside
  the window return `KEY_EXPIRED` — separates rotation from
  compromise-driven revocation while preserving historical pin
  verifiability.
- Replay-protection check: callers may supply
  `expected_record_id` / `expected_collection_id` / `expected_tenant_id`,
  verified against the reserved `vectorpin.*` keys in `extra`. Returns
  `RECORD_MISMATCH` / `COLLECTION_MISMATCH` / `TENANT_MISMATCH` on
  divergence (spec §5 step 8).
- Spec failure-mode taxonomy expanded to include `KEY_EXPIRED`,
  `PARSE_ERROR`, the three `*_MISMATCH` codes, and `UNSUPPORTED_DTYPE`.

### Implementations

All three reference implementations produce byte-for-byte identical
canonical bytes and Ed25519 signatures from the same deterministic
seed (verified by `testvectors/v2.json` and the per-language
cross-language test).

#### Python

- `PROTOCOL_VERSION = 2`, `DOMAIN_TAG = b"vectorpin/v2\x00"` exported
  from `vectorpin.attestation`.
- `Pin.from_*` strict schema: 64 KiB cap, type/regex/length checks on
  every field, `vec_dtype` allowlist, sig length 64 enforced.
- `Verifier` (strict v2) and `LegacyV1Verifier` (opt-in v1+v2).
- `Verifier.verify(..., expected_record_id=..., expected_collection_id=..., expected_tenant_id=...)`
  enforces replay-protection bindings.
- `KeyEntry` carries `(valid_from, valid_until)`; `KEY_EXPIRED` fires
  per §7.

#### Rust

- `pub const DOMAIN_TAG: &[u8] = b"vectorpin/v2\x00"`,
  `pub const PROTOCOL_VERSION: u32 = 2` exported.
- New `VerifyError` variants: `KeyExpired`, `ParseError(String)`,
  `RecordMismatch`, `CollectionMismatch`, `TenantMismatch`,
  `UnsupportedDtype(String)`.
- `VerifyOptions` builder carries replay-protection expected values.
- `LegacyV1Verifier` opt-in.

#### TypeScript

- Async signing/verifying API throughout (`signAsync` / `verifyAsync`).
  Drops the globally-mutable `ed25519.etc.sha512Sync` hook.
- `Signer.fromPrivateBytes` makes a defensive copy of the seed.
  `Signer.wipe()` zeros it.
- Pinned exact crypto deps: `@noble/ed25519@2.3.0`,
  `@noble/hashes@1.8.0`.
- Prototype-pollution guards in `pinFromDict`; strict base64url
  alphabet enforced before signature decode.

### Hardening — implementation surface

Beyond the wire-format break, the audit-driven hardening also closes
implementation-level findings:

- **Python CLI**: `vectorpin keygen` now writes the private seed with
  mode `0o600` via `O_EXCL` (no umask reliance, refuses to clobber an
  existing key); parent directory created with mode `0o700`. The
  public key is explicitly set to `0o644`.
- **Python adapters**: LanceDB validates `id_column` / `vector_column`
  / `pin_column` against an identifier regex and rejects `record_id`
  containing NUL, newline, or backslash. Qdrant and Pinecone refuse
  an `api_key` over `http://` for non-loopback hosts unless
  `VECTORPIN_ALLOW_INSECURE_HTTP=1` is set.
- **Python audit loop**: a single malformed pin in
  `audit-{lancedb,chroma,qdrant}` no longer aborts the run; bad rows
  are surfaced as `parse_error` and the audit continues.
- **Python `Signer.from_pem`**: requires explicit `password=...` or
  `allow_unencrypted=True` to load an unencrypted PEM. Default
  behavior refuses.
- **Python dependency bounds**: `cryptography>=42,<46`,
  `numpy>=1.26,<3` in `pyproject.toml`.
- **Rust**: `#![forbid(unsafe_code)]` on the crate.
  `Signer::generate` returns `Result<Self, SignerError::EmptyKeyId>`.
  `Signer::private_key_bytes` returns `Zeroizing<[u8; 32]>`.
  `vec_dim` cast via `u32::try_from` on signer + verifier sides.
  `Verifier::add_key` returns `Result<(), VerifyError::KeyDecodeFailed>`.
  `zeroize = "1"` added as a direct dep.
- **TypeScript**: switched to async signing/verifying API
  (`signAsync` / `verifyAsync`), dropping the globally-mutable
  `ed25519.etc.sha512Sync` hook. `Signer.fromPrivateBytes` makes a
  defensive copy. New `Signer.wipe()` zeros the seed. Module-load
  assertion that `crypto.getRandomValues` is available. Prototype-
  pollution guards in `pinFromDict`. Sanitized error detail strings
  (strip control chars, truncate). `@noble/ed25519@2.3.0` and
  `@noble/hashes@1.8.0` pinned to exact versions.

### Test vectors

- `testvectors/v2.json` — 4 positive fixtures covering f32, f64,
  `model_hash`, and `extra` with `vectorpin.record_id`. Each carries
  `expected_canonical_bytes_b64` for cross-language equality assertion.
- `testvectors/negative_v2.json` — 17 fixtures exercising every
  failure mode in spec §5: tampered vector, tampered source, wrong
  model, wrong `v`, wrong `kid`, bit-flipped sig, wrong sig length,
  unknown top-level field, non-string `extra` value, NaN in vector,
  NFD source, fractional-seconds `ts`, offset `ts`, lowercase `t`/`z`
  `ts`, record_id mismatch, oversize JSON.
- `testvectors/v1.json` and `testvectors/negative_v1.json` retained
  for `LegacyV1Verifier` coverage.

### Migration

Existing v1 pins do not verify under the strict default v2 verifier
in any language. To migrate a corpus:

1. Read each pin with `LegacyV1Verifier` (opt-in flag /
   constructor / class).
2. Re-sign with the v2 `Signer`, which writes `v: 2` and the new
   canonical bytes.
3. Write the re-signed pin back to the vector store.

Plain re-pinning preserves the bound `(source, vector, model)` triple
while replacing the now-deprecated v1 signature.

### Documentation

- New Zensical-rendered documentation site (`docs/`, `zensical.toml`):
  index, getting-started, pin-protocol, CLI guide, adapters, detectors,
  deployment, security, troubleshooting. The normative protocol
  reference remains `docs/spec.md`. Published at
  `https://docs.vectorpin.org/` via GitHub Pages.

## [0.1.1] — 2026-05-07

Patch release. No protocol changes; pins produced by 0.1.0 verify on
0.1.1 and vice-versa. Cross-language test vectors are unchanged from
0.1.0; the seed-based fixtures in `testvectors/v1.json` are byte-for-byte
identical.

### Added

- `audit-lancedb` CLI command. Walks a LanceDB table, verifies every
  pin (signature + vector hash, plus source hash if `--source-column`
  is supplied), and emits a JSON summary. Exit non-zero on any
  verification failure so it composes cleanly into CI / cron.
- `audit-chroma` CLI command. Same shape, against a Chroma collection
  (persistent or HTTP). Optional `--source-metadata-key` flag for
  source-text verification.
- `audit-qdrant` gained an optional `--source-payload-key` flag for
  parity with the new commands. Existing invocations are unaffected
  (signature + vector verification remains the default).

### Documentation

- Comprehensive [docs.rs landing page](https://docs.rs/vectorpin) for
  the Rust crate: overview, architecture table, failure-mode taxonomy,
  threat model, and runnable doctest examples on every public type.
- Doctest count grew from 1 to 12 across `attestation`, `hash`,
  `signer`, and `verifier`. Strict `cargo doc` build now passes under
  `-D missing_docs -D rustdoc::broken_intra_doc_links
  -D rustdoc::missing_crate_level_docs`.
- Crates.io README rewritten to match the docs.rs landing-page tone.
- Repository URL fixed in `pyproject.toml` (was `thirdkey/vectorpin`,
  now `ThirdKeyAI/VectorPin`).
- Author string aligned to `"Jascha Wanger / ThirdKey.ai"` across all
  three packaging configs to match the rest of the Trust Stack.

## [0.1.0] — 2026-05-07

Initial public release. Protocol version: 1.

### Added

#### Core protocol
- `Pin` and `PinHeader` attestation format with sorted-key, no-whitespace
  canonical JSON encoding for deterministic signing.
- SHA-256 over UTF-8 NFC-normalized source text.
- SHA-256 over canonical little-endian f32/f64 vector bytes.
- Ed25519 signing and verification.
- URL-safe base64 (no padding) wire encoding for signatures.
- Wire-format specification at [`docs/spec.md`](docs/spec.md), self-contained
  for cross-language reimplementation.

#### Python implementation (`src/vectorpin/`)
- `Signer.generate(key_id)` and `Signer.from_private_bytes(raw, key_id)`.
- `Signer.pin(source, model, vector)` returning a signed `Pin`.
- `Verifier(public_keys)` with structured `VerificationResult` outcomes:
  `OK`, `UNSUPPORTED_VERSION`, `UNKNOWN_KEY`, `SIGNATURE_INVALID`,
  `VECTOR_TAMPERED`, `SOURCE_MISMATCH`, `MODEL_MISMATCH`, `SHAPE_MISMATCH`.
- Multi-key registry for rotation support.
- `Pin.to_json()` / `Pin.from_json()` round-trip.

#### Rust implementation (`rust/vectorpin/`)
- Byte-for-byte compatible with the Python reference.
- Same canonical bytes, same Ed25519 signatures.
- `Signer`, `Verifier`, `Pin`, `PinHeader` types with the same
  failure-mode taxonomy.
- Full unit-test coverage plus cross-language fixtures and one doctest.

#### TypeScript implementation (`typescript/`)
- Third reference implementation, byte-for-byte compatible with
  Python and Rust. Pure JavaScript via `@noble/ed25519` and
  `@noble/hashes`, no native deps; works in Node 20+, Deno, Bun, and
  Cloudflare Workers.
- `Signer.generate(keyId)` / `Signer.fromPrivateBytes(raw, keyId)`.
- `Signer.pin({ source, model, vector, ... })` named-options API.
- `Verifier(publicKeys)` with the same failure-mode taxonomy as the
  Python and Rust ports; string-valued `VerifyErrorCode` matches the
  Python wire-form values.
- `pinToJSON` / `pinFromJSON` round-trip.
- ESM-only, ships TypeScript declarations.

#### Cross-language test vectors (`testvectors/`)
- `v1.json`: positive fixtures with deterministic seed, consumed by
  the Python, Rust, and TypeScript test suites.
- `negative_v1.json`: tamper-detection fixture, consumed by all three
  ports.
- CI workflow regenerates fixtures on every Python-side change and
  fails on byte drift, preventing silent compatibility breakage.

#### Adapters
Lazy-loaded via `__getattr__` on `vectorpin.adapters`; backend client
libraries are only imported when the corresponding adapter is used.
- `LanceDBAdapter` *(default backend)*: embedded, file-based, no
  daemon. Pin lives as a typed string column on the table; Lance's
  versioned commit protocol makes (vector, pin) writes atomic. Matches
  the Symbiont runtime's default vector backend. Install with
  `pip install 'vectorpin[default]'` or `'vectorpin[lancedb]'`.
- `ChromaAdapter`: Chroma `metadatas` field. Install with
  `pip install 'vectorpin[chroma]'`.
- `PineconeAdapter`: Pinecone v5+ client (the package was renamed
  upstream from `pinecone-client` to `pinecone`). Install with
  `pip install 'vectorpin[pinecone]'`.
- `QdrantAdapter`: production Qdrant integration via `qdrant-client`.
  Install with `pip install 'vectorpin[qdrant]'`.

#### Detectors
- `IsolationForestDetector` and `OneClassSVMDetector`: defensive
  baselines from sklearn. Lazily imported; install with
  `pip install 'vectorpin[detectors]'`.

#### CLI (`vectorpin`)
- `keygen`: generate Ed25519 key pairs.
- `pin`: sign a (text, vector) pair.
- `verify-pin`: verify a pin against ground-truth source/vector.
- `audit-qdrant`: walk a Qdrant collection and report on every record.

#### Microbenchmarks
- `rust/vectorpin/benches/perf.rs` (criterion) and
  `scripts/bench_python.py` (`time.perf_counter_ns`). Per-op coverage
  of `hash_text`, `hash_vector`, `sign`, `verify_full`,
  `verify_signature_only` across vector dim ∈ {384, 768, 1024, 3072}
  and text length ∈ {128, 1024, 8192}. Sub-millisecond per vector on
  commodity hardware.

#### Documentation
- README with Python, Rust, and TypeScript quick-start.
- `docs/spec.md` — protocol v1 specification.
- `examples/basic_usage.py` and `examples/basic_usage.rs`.
- Companion preprint (Zenodo DOI
  [10.5281/zenodo.20058256](https://doi.org/10.5281/zenodo.20058256))
  documenting the threat model and defended attack class.

### Known limitations

- Adapter coverage is partial: LanceDB, Chroma, Pinecone, and Qdrant
  ship; FAISS and pgvector are planned for a follow-up release. The
  recommended path for FAISS users is to use `LanceDBAdapter`
  (embedded, has metadata column natively) and treat FAISS as a
  derived index.
- A Go port is planned but not yet shipped.
- Record-id and collection-id binding currently lives under the
  `extra` field; promotion to top-level fields is a candidate for
  protocol v1.1.

[0.1.1]: https://github.com/ThirdKeyAI/VectorPin/releases/tag/v0.1.1
[0.1.0]: https://github.com/ThirdKeyAI/VectorPin/releases/tag/v0.1.0
