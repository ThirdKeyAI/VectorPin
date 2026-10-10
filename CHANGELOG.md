# Changelog

All notable changes to VectorPin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Security fixes from the 2026-10 review of the v0.2.0 release. IDs refer
to that review's findings. The wire format is unchanged (still `v: 2`);
the verifier contract is stricter, so pins over wider-than-persisted
input and audits of partially pinned stores now fail where they used
to pass — see "Behavior changes" below.

### Security

- **VP-1 (High)** — Verifiers cast a supplied vector to the pinned dtype
  before hashing, so an f64 store checked against an f32 pin left
  ~28 bits per element unverified, and every adapter coerced to f32
  before the verifier saw the data. All three verifiers now refuse a
  vector wider than `vec_dtype` (`SHAPE_MISMATCH`; Rust
  `VerifyError::PrecisionWidening`), adapters return the store's native
  dtype, and the Python/TypeScript signers default `vec_dtype` to the
  input's native dtype (Rust already did). Spec §3.2 gains the precision
  rule.
- **VP-2 (High)** — The audit CLI treated missing or empty pins as
  harmless `unpinned` and exited 0. Unpinned records now fail unless
  `--allow-unpinned`; empty pin fields are `parse_error`; every failing
  record is named. A signed collection manifest (count + Merkle root
  over `record_id → vec_hash`, `vectorpin.manifest`, `--write-manifest`
  / `--manifest`) catches deleted and inserted records.
- **VP-3 (High)** — The audit never enforced record / collection /
  tenant / model bindings. `vectorpin.record_id` is now checked against
  the record it sits on by default (`--no-record-id-check` to disable);
  `--collection-id`, `--tenant-id`, `--expected-model`,
  `--expected-model-hash` added to every `audit-*` command and to
  `verify-pin`.
- **VP-4 (High, design)** — README, `docs/security.md`,
  `docs/deployment.md`, and the Rust crate docs now state that the
  protected interval begins at signing, that a writer upstream of the
  signer is out of scope, and that the signer should run as a separate
  service / KMS; the previously contradictory threat-model bullets are
  reconciled.
- **VP-5 (Medium)** — `valid_until` was keyed on the signer-chosen `ts`,
  so a compromised key could backdate forgeries into the window. The
  limitation is documented (spec §7, §9) and every verifier takes a
  `trusted_time` / `trustedTime` / `VerifyOptions::trusted_time`
  (verifier-trusted ingestion instant) against which the window is
  evaluated; a `ts` after the trusted time is rejected.
- **VP-6 (Medium)** — Lone surrogates crashed the Python verifier and
  were emitted by the TypeScript signer. Rejected at parse and sign time
  in Python and TypeScript (Rust already refused them); `hash_text`
  refuses unencodable text; `verify()` never raises in any port.
- **VP-7 (Medium)** — The audit stopped at the first malformed pin
  because the adapter generator was finalized by the exception.
  Adapters yield error-carrying records (`PinnedRecord.parse_error`),
  the loop catches any adapter failure, and a mid-corpus malformed pin
  is covered by tests.
- **VP-8 (Medium)** — CI never ran the TypeScript suite. Added a
  `typescript` job; the fixtures job now runs every port's
  cross-language tests after regenerating `testvectors/`.
- **VP-9 (Medium)** — The Rust `ts` parser accepted impossible calendar
  dates and could underflow `u32` before the signature check. All three
  parsers now require a valid proleptic-Gregorian instant; Rust uses
  checked `i64` arithmetic and exports `parse_ts_unix`.
- **VP-10 (Medium)** — `model_hash` could not be checked.
  `expected_model_hash` added to all three verifiers and the CLI;
  `vectorpin.hash_files` implements the spec §4.1 convention, which is
  now spelled out.
- **VP-11 (Low)** — A naive `datetime` in `KeyEntry` raised `TypeError`
  from `verify()`; rejected at construction instead.
- **VP-12 (Low)** — `sig` decoding diverged (Python lenient, TypeScript
  padding-tolerant, Rust strict). Python and TypeScript now accept only
  the canonical URL-safe, unpadded, zero-trailing-bits encoding.
- **VP-13 (Low)** — `v: 2.0` parsed in Python/TypeScript, Rust truncated
  `v` with `as u32`, and `extra: null` was accepted by Rust/TypeScript.
  All ports require a minimal integer literal and reject `extra: null`.
- **VP-14 (Low)** — Dict-path pins bypassed the size cap and `kid` /
  `model` were unbounded. Per-field caps (`kid` 256 B, `model` 1 KiB)
  apply on every parse path before normalization; spec §4.3 updated.
- **VP-15 (Low)** — Chroma HTTP adapter sent auth headers over plaintext
  without the TLS guard the other adapters have. Guard added;
  `audit-chroma --header NAME=VALUE` wired through it.
- **VP-16 (Low)** — ed25519-dalek `zeroize` feature enabled so the Rust
  `SigningKey` is wiped on drop; the Python signer rejects empty
  vectors instead of emitting an unparseable `vec_dim=0` pin.
- **VP-17 (Info)** — Spec corrected: 13-byte domain tag, `\uXXXX` escapes
  for U+0000–U+001F only (U+007F emitted raw), and the three verifiers
  reordered to check source (step 5) before vector (step 6) as §5 says.
- **VP-18 (Info)** — TypeScript port no longer uses Node `Buffer`
  (pure-JS base64url codec, `utf8ByteLength`); README claims about
  Deno/Bun and the Symbiont integration qualified.

### Added

- `BaseAdapter.get_verified` / `iter_verified` read wrappers.
- Signed audit summaries (`--sign-summary-key`, `vectorpin
  verify-summary`, `vectorpin.sign_audit_summary` /
  `verify_audit_summary`).
- Warning when a group/world-readable `.priv` file is loaded
  (`VECTORPIN_QUIET_KEY_PERMS=1` silences it).
- Cross-language fixtures for float edge cases (signed zeros,
  subnormals, f32/f64 max, f64→f32 round-to-nearest-even ties), the
  widening channel, calendar-invalid timestamps, lone surrogates,
  padded / non-canonical `sig`, `v: 2.0`, `extra: null`, field caps,
  model-hash, collection / tenant, and KEY_EXPIRED cases.
- Property tests over canonical bytes in all three ports (hypothesis,
  proptest, fast-check) and VectorSmuggle-style perturbation tests.
- Supply-chain CI job (`cargo audit`, `npm audit --omit=dev`,
  `pip-audit`); `cryptography` upper bound removed.

### Behavior changes

- `Signer.pin` (Python) and `Signer.pin` (TypeScript) default
  `vec_dtype` to the input's native dtype instead of `f32`. Pin under
  the dtype your store persists; pass `vec_dtype="f32"` explicitly to
  keep the old behavior for 64-bit input.
- `Verifier.verify` rejects a vector wider than the pinned dtype as
  `SHAPE_MISMATCH` instead of casting it.
- `audit-*` commands fail on unpinned records unless `--allow-unpinned`
  and enforce `vectorpin.record_id` when a pin carries it.
- The Rust `VerifyError` enum gains `PrecisionWidening`; `VerifyOptions`
  gains `expected_model_hash` and `trusted_time`.

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
  `audit-{lancedb,chroma,qdrant}` no longer aborts the run with a
  traceback; the bad row is surfaced as `parse_error`. (Correction: in
  0.2.0 the walk still *ended* at that row because the adapter
  generator was finalized by the exception, so later records went
  unaudited; see VP-7 under Unreleased for the fix.)
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
