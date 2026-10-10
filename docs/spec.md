# VectorPin Protocol Specification

**Version:** 2
**Status:** Draft
**License:** Apache 2.0

This document specifies the wire format, canonicalization, and verification rules for VectorPin attestations. Anyone implementing VectorPin in another language should be able to read this document, ignore the Python reference implementation, and produce signatures and verifications that interoperate.

**Protocol version 2 is a wire-format break over v1.** It is not backwards-compatible with v1 pins. The break is motivated by a security audit (2026-05) that identified four cross-implementation issues: protocol version not bound to the signature, `kid` not bound to the signature, no domain separator, and underspecified canonicalization of floats, strings, and timestamps. See §12.

## 1. Goals

A VectorPin Pin is a compact attestation that travels with an embedding through a vector database. It guarantees that:

- The embedding matches a specific source text.
- The embedding was produced by a specific model.
- The pin was issued by a specific producer.
- None of the above has changed since issuance.
- Cross-protocol signature reuse with sister Trust-Stack protocols is prevented by a domain separator (§4.2).

Non-goals: confidentiality, access control, anti-replay across collections without explicit caller cooperation (§8, §5 step 7).

## 2. Cryptographic primitives

| Primitive | Algorithm |
|---|---|
| Hash | SHA-256 |
| Signature | Ed25519 over `domain_tag || canonical_json` |
| Domain separator | exact ASCII bytes `vectorpin/v2\x00` (13 bytes) |
| Encoding | URL-safe base64, no padding |

These are fixed for protocol version 2. Future versions MAY introduce alternatives but MUST bump the version field AND change the domain separator.

## 3. Canonical hashes

### 3.1 Text hashing

```
hash_text(s) := "sha256:" || hex(SHA-256(UTF-8(NFC(s))))
```

Text MUST be normalized to Unicode NFC before encoding. Implementations MUST reject input that cannot be normalized.

The same NFC requirement applies to **every string-typed field** in the pin (`model`, `kid`, `ts`, each `extra` key, each `extra` value). Implementations MUST normalize these to NFC before signing and MUST reject parsed pins whose string fields are not already in NFC form.

Implementations MUST reject any string field containing:

- Control characters in `U+0000`–`U+001F` (except none — control chars are always rejected).
- Bidirectional overrides `U+202A`–`U+202E`, `U+2066`–`U+2069`.

### 3.2 Vector hashing

```
hash_vector(v, dtype) := "sha256:" || hex(SHA-256(canonical_bytes(v, dtype)))
```

Where `canonical_bytes` produces:

1. The vector represented in the specified dtype (`f32` or `f64`). At sign time a signer MAY cast a wider input to the declared dtype (round-to-nearest-even); the pin then commits to the cast values and the store MUST persist exactly those values in that dtype.
2. Stored in little-endian byte order.
3. Packed contiguously, 1-D.

Implementations MUST reject vectors containing NaN, positive infinity, or negative infinity at sign time. `-0.0` and `+0.0` are distinct values and both valid; FTZ/DAZ floating-point modes MUST be disabled or vectors normalized before hashing.

**Precision rule (verify time).** The commitment is to the stored representation, not to a rounding of it. A verifier MUST refuse to hash a supplied vector whose native element width is greater than the width of `vec_dtype` (for example a 64-bit vector against an `f32` pin), reporting `SHAPE_MISMATCH` (or an implementation-specific equivalent) without casting. Casting first would make every value that rounds to the same `vec_dtype` value verify identically, leaving the discarded low-order bits — about 29 per element for f64 under f32 — as an unverified covert channel in any store that persists the wider type. A supplied vector narrower than `vec_dtype` MAY be widened (the widening is exact) but will only verify if the signed values were representable at that width. Adapters MUST hand the verifier the dtype the store persists, never a coerced one. Signers SHOULD default `vec_dtype` to the input's native dtype; operators SHOULD pin under the dtype their store persists.

Other dtypes are reserved for future protocol versions.

## 4. Pin format

### 4.1 Wire form

A Pin is a JSON object with the following fields. **No other top-level fields are permitted.** Implementations MUST reject pins containing unknown top-level keys.

| Field | Type | Required | Description |
|---|---|---|---|
| `v` | integer | yes | Protocol version. Must equal `2`. MUST be a JSON integer literal in minimal form: `2.0`, `2e0`, `true`, or a value outside the 32-bit unsigned range MUST be rejected (never truncated). |
| `kid` | string | yes | Identifier of the signing key. |
| `model` | string | yes | Embedding model identifier. |
| `model_hash` | string | no | Optional content hash of the model weights. When present, MUST equal `"sha256:" || hex(SHA-256(bytes(shard_1) || bytes(shard_2) || ...))` where the shards are every weight file of the model (e.g. `*.safetensors`, `*.bin`, `*.gguf`), ordered by their base filename in ASCII byte order (not locale order), each contributed as its raw on-disk bytes. Tokenizer and configuration files are excluded. A single-file model is the hash of that file. The Python reference implements this as `vectorpin.hash_files(paths)`. Implementations that cannot meet this convention MUST omit the field. The value is only as trustworthy as the signer that wrote it: verifiers that need to bind a specific model MUST compare it against an expectation (§5 step 7). |
| `source_hash` | string | yes | Hash of the source text (§3.1). |
| `vec_hash` | string | yes | Hash of the embedding (§3.2). |
| `vec_dtype` | string | yes | One of `"f32"` or `"f64"`. |
| `vec_dim` | integer | yes | Embedding dimensionality. Must be a positive integer ≤ 1,048,576. |
| `ts` | string | yes | UTC timestamp matching exactly the pattern `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`. No fractional seconds, no timezone offsets, no lowercase `t`/`z`. The value MUST also denote a real proleptic-Gregorian UTC instant: month `01`–`12`, day `01` through the length of that month (leap years honored), hour `00`–`23`, minute `00`–`59`, second `00`–`59`. Implementations MUST reject a regex-shaped but impossible value such as `2026-02-30T00:00:00Z` at parse time rather than rolling it into a different date. |
| `extra` | object | no | Map of UTF-8 string keys to UTF-8 string values. Values that are not strings MUST cause a parse error. `null` is not "absent": the field is either an object or not present at all. Reserved keys: see §8. |
| `sig` | string | yes | Ed25519 signature, URL-safe base64 with no padding. Decoded length MUST be exactly 64 bytes. Parsers MUST accept only the canonical encoding: the URL-safe alphabet (`A–Z a–z 0–9 - _`), no `=` padding, no characters from the standard alphabet, and zero-valued trailing bits in the final symbol. |

### 4.2 Canonicalization for signing

The signed byte sequence is:

```
signed_bytes := b"vectorpin/v2\x00" || canonical_json(header)
```

Where `header` is a JSON object containing **exactly** the following fields, in the order they would appear after lexicographic sorting: `extra` (if present and non-empty), `kid`, `model`, `model_hash` (if present), `source_hash`, `ts`, `v`, `vec_dim`, `vec_dtype`, `vec_hash`.

The `sig` field is excluded from the signed bytes. **Every other field, including `v` and `kid`, is included.** Including `v` defeats downgrade attacks (cannot strip new fields and present remainder to an older verifier); including `kid` defeats cross-key swap attacks (cannot re-attribute a signed pin to a different producer).

`canonical_json` is JSON with:

- All keys sorted lexicographically by Unicode code point (equivalent to ASCII sort for the well-formed v2 field set).
- No whitespace between tokens (separators are `,` and `:` with no surrounding spaces).
- UTF-8 encoding, NFC-normalized strings.
- `extra`, if present, with its keys sorted by the same rule. `extra` MUST be omitted if empty.
- `model_hash` omitted entirely if not set.
- Integers serialized in their minimal JSON form (no leading zeros, no exponent notation).
- Strings emit the JSON-standard escapes (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, `\uXXXX` for U+0000–U+001F only). All other characters, including U+007F, MUST be emitted as raw UTF-8 bytes (not as `\u` escapes). Non-ASCII NFC code points are emitted directly. (Control characters are rejected by §3.1 before canonicalization, so in practice no `\uXXXX` escape ever appears in a conforming pin's canonical bytes.)

The 13-byte domain tag is prepended to `canonical_json(header)` and the concatenation is fed to Ed25519 signing. Verifiers reconstruct the same bytes from the parsed pin.

### 4.3 Size limits

To bound parser resource consumption and prevent DoS through hostile pins, conforming v2 implementations MUST enforce:

| Limit | Maximum |
|---|---|
| Total pin JSON, UTF-8 byte length | 64 KiB (65,536 bytes) |
| `extra` entry count | 32 |
| Any `extra` key, UTF-8 byte length | 128 bytes |
| Any `extra` value, UTF-8 byte length | 1 KiB (1,024 bytes) |
| `vec_dim` | 1,048,576 (2^20) |
| `sig`, decoded byte length | exactly 64 (Ed25519 signature) |
| `kid`, UTF-8 byte length | 256 bytes |
| `model`, UTF-8 byte length | 1 KiB (1,024 bytes) |

Verifiers MUST reject oversized pins before parsing the signature. The per-field caps MUST be applied before NFC normalization and the control-character scan, and they MUST apply on every parse path — including implementations that accept an already-decoded object (a database JSONB value or a client payload) rather than JSON text, which the total-size cap does not reach.

### 4.4 Example

```json
{
  "v": 2,
  "kid": "prod-2026-05",
  "model": "text-embedding-3-large",
  "source_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "vec_hash": "sha256:0123...",
  "vec_dtype": "f32",
  "vec_dim": 3072,
  "ts": "2026-05-05T12:00:00Z",
  "sig": "MEUCIQD..."
}
```

The canonical bytes for this pin (excluding `sig`) begin with the 13-byte `vectorpin/v2\x00` tag, followed by `{"kid":"prod-2026-05","model":"text-embedding-3-large","source_hash":"sha256:...","ts":"2026-05-05T12:00:00Z","v":2,"vec_dim":3072,"vec_dtype":"f32","vec_hash":"sha256:..."}`.

## 5. Verification

A verifier MUST, in order:

0. Reject pins whose serialized JSON exceeds the size limits in §4.3 before parsing.
1. Reject pins whose `v` field is unknown to it. A strict v2 verifier rejects any `v != 2`. A migration-mode verifier MAY dispatch `v == 1` pins to a legacy v1 verifier; legacy mode MUST be opt-in and SHOULD be disabled by default.
2. Reject pins whose `kid` is not in its key registry, OR whose registry entry's `(valid_from, valid_until)` window excludes `ts` (see §7).
3. Reject pins containing unknown top-level fields, non-string `extra` values, lone surrogate code points, calendar-invalid `ts`, over-cap string fields, or any string field that is not in NFC form.
4. Reconstruct the canonical byte sequence (§4.2) — including the domain tag — and verify `sig` against the registered public key for `kid`.
5. If a ground-truth source string was supplied, recompute `hash_text(source)` and compare to `source_hash`.
6. If a ground-truth vector was supplied: check that its shape matches `vec_dim`; refuse it if its native element width exceeds that of `vec_dtype` (§3.2 precision rule) — never cast first; reject it if it contains NaN/Inf; then recompute `hash_vector(vector, vec_dtype)` and compare to `vec_hash`.
7. If an expected model identifier was supplied, compare to `model`. If an expected `model_hash` was supplied, the pin MUST carry an equal `model_hash`; a pin without one fails.
8. If the caller supplied an expected `vectorpin.record_id` / `vectorpin.collection_id` / `vectorpin.tenant_id`, the verifier MUST compare against the value in `extra` and reject on mismatch.

A verifier MUST NOT raise or throw on account of pin content or supplied ground truth: every outcome, including an internal failure while evaluating a hostile record, MUST be returned as a structured result (at worst `PARSE_ERROR`) so that a read path can never be turned into an exception path. Configuration errors (for example a malformed registry entry) MAY raise, but only at configuration time.

Verifiers MUST distinguish at least these failure modes (the reference implementations use the names below; other implementations MAY use different names but MUST distinguish the cases):

- `UNSUPPORTED_VERSION`
- `UNKNOWN_KEY`
- `KEY_EXPIRED`
- `PARSE_ERROR` — pin JSON exceeds size limits, contains unknown top-level fields, has non-string `extra` values, or fails type/format validation.
- `SIGNATURE_INVALID`
- `VECTOR_TAMPERED`
- `SOURCE_MISMATCH`
- `MODEL_MISMATCH` — `model` or `model_hash` differs from the caller's expectation.
- `SHAPE_MISMATCH` — dimension mismatch, or a supplied vector wider than `vec_dtype` (§3.2 precision rule; an implementation MAY use a distinct name for the widening case, as the Rust reference does with `PrecisionWidening`).
- `RECORD_MISMATCH` / `COLLECTION_MISMATCH` / `TENANT_MISMATCH`

## 6. Storage conventions

Adapter implementations SHOULD store pins under the metadata key `vectorpin`. Backends without free-form metadata fields are out of scope for this version of the protocol — provenance must travel with the data.

## 7. Key rotation and revocation

Verifiers MUST support multiple `kid` -> public key mappings simultaneously, each with an optional validity window `(valid_from, valid_until)` of RFC 3339 timestamps. Issuers rotate by:

1. Generating a new keypair with a fresh `kid`.
2. Adding the new public key to all relevant verifier registries, with a `valid_from` no earlier than the moment the new private key becomes operational.
3. Switching production signing to the new private key.
4. Optionally re-pinning the corpus over time.
5. Setting `valid_until` on the old key entry to the rotation cutover instant (do not remove the entry — historical pins must continue to verify against it).

Old pins continue to verify against the old public key as long as their `ts` falls within the old key's `(valid_from, valid_until)` window.

### Revocation distinct from rotation

If a private key is **compromised** (as opposed to merely rotated for hygiene), the corresponding `kid` entry MUST be marked with `valid_until` set to the latest moment the key is believed to have been uncompromised. Pins with `ts` after that instant return `KEY_EXPIRED`; pins with `ts` before it continue to verify. This preserves the integrity of historical pins.

**Limitation.** `ts` is written by the signer and is under the signature, so the only party who can set it is whoever holds the key — including the attacker this mechanism exists to stop. A post-compromise forgery whose `ts` is backdated to before `valid_until` verifies. On its own, the window therefore bounds *honest* signers (it stops a legitimately rotated-out key from being used by mistake); it does not, by itself, invalidate what an attacker produces after compromise.

To close that gap a verifier MUST obtain the evaluation instant from a clock the key holder cannot write. The reference implementations expose this as a caller-supplied trusted time (`trusted_time` / `trustedTime` / `VerifyOptions::trusted_time`), intended to carry the store's own ingestion timestamp, a database-side `created_at` the signer cannot set, or a timestamp-authority countersignature. When it is supplied the window is evaluated against that instant instead of `ts`, and a pin whose `ts` postdates it is rejected (`KEY_EXPIRED`) because no honest signer can sign a record after it was ingested. Deployments that need revocation to be effective against a compromised key MUST record such a time at ingestion and supply it at verification.

Operators SHOULD pair this with a transparency-log entry (e.g., sigstore Rekor or a project-specific append-only log) for the revocation event itself, so that downstream verifiers can detect a malicious registry rollback.

The protocol does not specify a revocation file format in v2; this is intentionally out of band so deployments can integrate with existing PKI / sigstore infrastructure. The minimum requirement on a v2 verifier is to honor the `(valid_from, valid_until)` window however it is delivered.

## 8. Reserved `extra` keys

The `vectorpin.` prefix is reserved by this specification and MUST NOT be used by implementations for any purpose other than the keys defined here. Reserved v2 keys, all optional:

| Key | Type | Meaning |
|---|---|---|
| `vectorpin.collection_id` | string | Identifier of the vector-store collection / index this pin belongs to. |
| `vectorpin.record_id` | string | Identifier of the specific record this pin attests. |
| `vectorpin.tenant_id` | string | Identifier of the multi-tenant logical namespace the pin lives in. |

Implementations that need replay protection (cross-record, cross-collection, or cross-tenant) SHOULD use these reserved keys, and verifiers MUST enforce them when the caller supplies an expected value (§5 step 8). Because every `extra` entry is signed, the values are tamper-evident.

A future v3 may promote these to required top-level fields. The current v2 design keeps them inside `extra` so operators can adopt replay-protection incrementally per collection.

## 9. Security considerations

- **Replay**: Pins are not bound to a specific record id at the wire format level. An attacker who copies a pin from one record to another can pass verification only if the vector and source they paste alongside match the pin. Implementations that need stronger replay protection SHOULD use the reserved `vectorpin.collection_id` / `vectorpin.record_id` / `vectorpin.tenant_id` keys defined in §8, and verifiers MUST enforce them when the caller supplies an expected value (§5 step 8).
- **Time**: The `ts` field is informational *for the pin* but load-bearing for revocation: verifiers MUST consult `(valid_from, valid_until)` on the `kid` registration (§7) and reject pins whose `ts` falls outside that window. Because `ts` is signer-chosen, revocation is only effective against a compromised key when the window is evaluated against a verifier-trusted time (§7).
- **Precision**: A verifier that casts a wider stored vector to `vec_dtype` before hashing accepts any modification confined to the discarded bits. Verifiers MUST refuse wider vectors (§3.2) and adapters MUST surface the store's native dtype.
- **Set integrity**: Pins attest to records, not to the set of records. Deletion of a pinned record, insertion of an unpinned one, and blanking of a pin field change no signature. Verification drivers SHOULD treat an unpinned or empty-pin record as a failure by default, and deployments SHOULD commit to the record set out-of-band (the Python reference ships a signed per-collection manifest: record count plus a Merkle root over `record_id → vec_hash`, signed under the distinct domain tag `vectorpin/manifest/v1\x00`).
- **Signing boundary**: The protected interval begins at signing. A writer with access to the component that invokes the signer — or upstream of it — obtains legitimately signed pins for whatever it writes. Signing SHOULD run in a separate service or KMS the ingestion pipeline cannot invoke arbitrarily.
- **Key custody**: An attacker with the private signing key can produce arbitrary pins. Treat the signing key as a high-value secret. Reference implementations write private keys with mode `0600`; production deployments SHOULD use a KMS or hardware-backed signer rather than file-system keys.
- **Source-time integrity**: VectorPin attests to the relationship between source and vector at pin time. It does not attest that the source itself was authentic at ingestion. Pair VectorPin with source-side controls (signed ingestion logs, document provenance) where this matters.
- **DoS via malformed pins**: Without the §4.3 size limits, a single hostile pin can exhaust verifier resources. Implementations MUST enforce these limits before reaching the signature path.
- **Domain separation**: The `vectorpin/v2\x00` tag prevents cross-protocol signature lift attacks. A signature produced by a VectorPin signer cannot validate against any non-VectorPin verifier (and vice-versa) even if the same Ed25519 key is used. Operators are NOT required to use VectorPin-only keys, but doing so is RECOMMENDED.

## 10. Key distribution

The protocol assumes a verifier has access to a registry mapping `kid` to `(public_key, valid_from, valid_until)`. How that registry is populated is out of scope, but the following SHOULD apply to any production deployment:

- **Fingerprint format**: Operators identifying a key out of band (Slack, email, ticket) SHOULD use `SHA-256(pubkey_bytes)` truncated to the first 16 hex digits, formatted as four colon-separated quads, e.g. `1f3a:7b22:9e0d:c4f1`.
- **Production registries SHOULD reference a transparency log entry** (e.g., sigstore Rekor) for each `kid` registration and revocation. The log entry binds the key material to a publicly observable, append-only history, allowing downstream verifiers to detect a malicious registry rollback.
- **Trust-on-first-use (TOFU) is NOT RECOMMENDED for new pins** unless the operator has explicitly opted in. A verifier that auto-registers any `kid` it encounters provides no integrity guarantee — it is a checksum, not a signature.
- **Per-tenant key separation**: Multi-tenant deployments SHOULD issue separate `kid`s per tenant rather than share a single producer key, so that compromise of one tenant's environment cannot forge pins for another tenant.

## 11. Versioning

This is protocol version 2. Future versions MAY:

- Add new optional fields under `extra`-style namespaces.
- Add new dtype identifiers.
- Add new signature/hash algorithms (with corresponding identifiers).

A change is breaking iff a v2 verifier would silently accept a v3 pin as valid when the v3 pin's additional semantics matter. Such changes MUST bump the major version AND change the domain separator (§2). Including `v` in the signed canonical bytes (§4.2) plus the size limits (§4.3) prevent downgrade attacks where an attacker strips new fields and presents the remainder to an older verifier.

## 12. Changes from v1

The v1 → v2 wire-format break addresses these audit-identified issues:

1. **`v` was not in the signed payload** — v1 verifiers could not detect a downgrade where an attacker flipped `v: 2` to `v: 1` on a v2 pin. v2 includes `v` in the canonical bytes (§4.2).
2. **`kid` was not in the signed payload** — an attacker who could swap `(kid, sig)` pairs could re-attribute a pin to a different producer. v2 includes `kid` in the canonical bytes.
3. **No domain separator** — a VectorPin signature was structurally identical to any other "signed canonical JSON" message, enabling cross-protocol signature reuse against sister Trust-Stack protocols. v2 prepends a 13-byte `vectorpin/v2\x00` tag.
4. **Float canonicalization underspecified** — v1 said "little-endian, contiguous" but didn't specify NaN/Inf handling. v2 requires rejection of NaN/Inf at sign time; `-0.0` and `+0.0` are distinct.
5. **String canonicalization underspecified** — v1 required NFC for `source` only. v2 requires NFC for every string field, plus rejection of control characters and bidi overrides.
6. **`extra` value types underspecified** — v1 said "object" with no constraint. v2 is strictly `map<string, string>`, with rejection at parse.
7. **Timestamp format underspecified** — v1 allowed any RFC 3339 string. v2 requires exact pattern `YYYY-MM-DDTHH:MM:SSZ`.
8. **Unknown top-level fields permitted** — v1 was silent. v2 verifiers MUST reject unknown top-level keys.
9. **Size limits absent** — v1 had no DoS protection. v2 specifies size limits (§4.3) as a verifier MUST.

v1 pins are not directly verifiable by a strict v2 verifier. Implementations MAY ship a legacy v1 verifier for migration purposes; it MUST be opt-in.
