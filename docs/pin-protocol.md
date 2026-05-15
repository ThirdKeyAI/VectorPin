# Pin Protocol

This page walks through the VectorPin v2 wire format and verification order at a level useful to library users. For the normative specification, see [spec.md](spec.md).

---

## Overview

A **Pin** is a compact JSON attestation that commits to five things:

| Commitment | How |
|---|---|
| Source text | SHA-256 of UTF-8 NFC-normalized bytes |
| Embedding model | Identifier string (and optional `model_hash` over weight shards) |
| Vector | SHA-256 of canonical little-endian dtype bytes |
| Producer | Ed25519 signature over `domain_tag \|\| canonical_json(header)` |
| Time | RFC 3339 timestamp `YYYY-MM-DDTHH:MM:SSZ` |

The pin travels with the embedding through the vector DB, stored under metadata key `vectorpin`. Verification recomputes the hashes, checks the signature against a registered public key, and reports a distinct outcome for each failure mode.

---

## Wire Format

A v2 Pin is a JSON object with **exactly** these top-level fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `v` | integer | yes | Protocol version. Must equal `2`. |
| `kid` | string | yes | Identifier of the signing key. |
| `model` | string | yes | Embedding model identifier. |
| `model_hash` | string | no | Optional `sha256:` hash over concatenated weight shards. |
| `source_hash` | string | yes | `sha256:` hex of NFC-normalized source text. |
| `vec_hash` | string | yes | `sha256:` hex of canonical little-endian vector bytes. |
| `vec_dtype` | string | yes | `"f32"` or `"f64"`. |
| `vec_dim` | integer | yes | Embedding dimensionality, `1 ≤ vec_dim ≤ 2^20`. |
| `ts` | string | yes | UTC timestamp matching `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`. |
| `extra` | object | no | `map<string, string>`. Reserved keys: see [Reserved Keys](#replay-protection). |
| `sig` | string | yes | Ed25519 signature, URL-safe base64, no padding, 64 bytes decoded. |

**Unknown top-level fields cause `PARSE_ERROR`.** This is a verifier MUST — it defeats downgrade attacks where an attacker strips new fields and presents the remainder to an older verifier.

### Example

```json
{
  "v": 2,
  "kid": "prod-2026-05",
  "model": "text-embedding-3-large",
  "source_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "vec_hash": "sha256:0123abcd...",
  "vec_dtype": "f32",
  "vec_dim": 3072,
  "ts": "2026-05-15T12:00:00Z",
  "sig": "MEUCIQD..."
}
```

### Size Limits

| Limit | Maximum |
|---|---|
| Total pin JSON, UTF-8 byte length | 64 KiB |
| `extra` entry count | 32 |
| Any `extra` key, UTF-8 byte length | 128 bytes |
| Any `extra` value, UTF-8 byte length | 1 KiB |
| `vec_dim` | 1,048,576 (2^20) |
| `sig`, decoded byte length | exactly 64 |

Verifiers reject oversized pins **before** parsing the signature, to bound resource use under hostile input.

---

## Canonicalization

The signed byte sequence is:

```
signed_bytes := b"vectorpin/v2\x00" || canonical_json(header)
```

The 13-byte domain tag prevents cross-protocol signature reuse — a VectorPin signature cannot validate against a sister Trust-Stack protocol (SchemaPin, AgentPin) even if the same Ed25519 key is reused.

`canonical_json` has fixed rules:

- All keys sorted lexicographically by Unicode code point.
- No whitespace between tokens (separators are `,` and `:`, no surrounding spaces).
- UTF-8 encoding, NFC-normalized strings.
- `extra` omitted if empty; otherwise keys sorted by the same rule.
- `model_hash` omitted entirely if not set.
- Integers in minimal JSON form (no leading zeros, no exponent).
- Strings use JSON-standard escapes (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, `\uXXXX` for `U+0000`–`U+001F` and `U+007F`). All other characters are raw UTF-8.

The `sig` field is excluded from `signed_bytes`. **Every other field — including `v` and `kid` — is included.** This defeats:

- **Version downgrade** — Cannot flip `v: 2` to `v: 1` to fool a legacy verifier.
- **Key swap** — Cannot re-attribute `(pin, sig)` to a different producer by editing `kid`.

### String Hygiene

All string fields (`model`, `kid`, `ts`, `extra` keys and values, and the source text) MUST be NFC-normalized and MUST NOT contain:

- Control characters in `U+0000`–`U+001F`.
- Bidirectional overrides `U+202A`–`U+202E`, `U+2066`–`U+2069`.

Implementations reject both at sign time and at parse time.

### Vector Hygiene

Vectors MUST be free of `NaN`, `+Inf`, `-Inf` at sign time. `-0.0` and `+0.0` are distinct values and both valid; FTZ/DAZ floating-point modes must be disabled or vectors normalized before hashing.

---

## Verification Order

A conforming verifier MUST execute these steps in order. Short-circuit on the first failure and return the distinct outcome.

### 0. Size check

If the serialized JSON exceeds any size limit above, return `PARSE_ERROR` without parsing.

### 1. Version check

If `v != 2` (or `v != 1` in legacy mode if explicitly enabled), return `UNSUPPORTED_VERSION`.

### 2. Key registry lookup

If `kid` is not in the verifier's registry, return `UNKNOWN_KEY`.

If `kid` is registered but `ts` falls outside the entry's `(valid_from, valid_until)` window, return `KEY_EXPIRED`. This is how revocation works in v2 — see [Key Rotation](#key-rotation-and-revocation).

### 3. Structural validation

If the pin contains unknown top-level fields, non-string `extra` values, malformed `ts`, or any string field not in NFC form, return `PARSE_ERROR`.

### 4. Signature

Reconstruct `signed_bytes = "vectorpin/v2\x00" || canonical_json(header)` and verify `sig` against the registered public key for `kid`. On failure, return `SIGNATURE_INVALID`.

### 5. Source check

If the caller supplied a ground-truth source string, recompute `hash_text(source)` and compare to `source_hash`. On mismatch, return `SOURCE_MISMATCH`.

### 6. Vector check

If the caller supplied a ground-truth vector:

1. Compare its shape to `vec_dim`. On mismatch, return `SHAPE_MISMATCH`.
2. Reject if the vector contains `NaN`/`Inf`, returning `PARSE_ERROR`.
3. Recompute `hash_vector(vector, vec_dtype)` and compare to `vec_hash`. On mismatch, return `VECTOR_TAMPERED`.

### 7. Model check

If the caller supplied an expected model identifier, compare to `model`. On mismatch, return `MODEL_MISMATCH`.

### 8. Replay-protection check

If the caller supplied an expected `vectorpin.record_id`, `vectorpin.collection_id`, or `vectorpin.tenant_id`, the verifier MUST compare against the value in `extra` and return `RECORD_MISMATCH` / `COLLECTION_MISMATCH` / `TENANT_MISMATCH` on mismatch. See [Replay Protection](#replay-protection).

If every applicable step passes, return `OK`.

---

## Key Rotation and Revocation

Verifier registries hold multiple `kid → (public_key, valid_from, valid_until)` entries simultaneously. This is what makes both rotation and revocation work cleanly.

### Rotation (hygiene)

1. Generate a new keypair with a fresh `kid`.
2. Add the new public key to all verifier registries, with `valid_from` no earlier than when the new private key becomes operational.
3. Switch production signing to the new private key.
4. Optionally re-pin the corpus over time.
5. Set `valid_until` on the old key entry to the rotation cutover instant. **Do not remove the entry** — historical pins must continue to verify against it.

Old pins continue to verify against the old key as long as their `ts` falls within the old key's `(valid_from, valid_until)` window.

### Revocation (compromise)

If a private key is compromised — as opposed to merely rotated — set `valid_until` on the `kid` entry to the latest moment the key is believed to have been uncompromised. Pins with `ts` after that instant return `KEY_EXPIRED`; pins with `ts` before it continue to verify. Historical pins stay valid; anything an attacker could forge post-compromise is rejected.

Pair this with a transparency-log entry (e.g., sigstore Rekor) for the revocation event itself, so downstream verifiers can detect a malicious registry rollback.

---

## Replay Protection

Pins are not bound to a specific record id at the wire format level. An attacker who copies a pin from record A to record B can pass verification only if the vector and source they paste alongside also match — but in a corpus full of near-duplicates, this is a real concern.

The `extra` map carries reserved keys for this:

| Reserved Key | Type | Meaning |
|---|---|---|
| `vectorpin.collection_id` | string | Identifier of the vector-store collection / index. |
| `vectorpin.record_id` | string | Identifier of the specific record this pin attests. |
| `vectorpin.tenant_id` | string | Identifier of the multi-tenant logical namespace. |

Every `extra` entry is signed, so the values are tamper-evident. Implementations that need stronger replay protection SHOULD set these at pin time and verifiers MUST enforce them when the caller supplies an expected value.

The `vectorpin.` prefix is reserved for this specification — implementations MUST NOT define their own keys under it.

---

## Cross-Language Compatibility

The Python, Rust, and TypeScript implementations produce byte-for-byte identical pins, locked together by [shared test vectors](https://github.com/ThirdKeyAI/VectorPin/blob/main/testvectors/v2.json) consumed in all three test suites. A pin produced in any one of them verifies in the other two.

Concretely, this means:

- Pinning can happen in your Rust ingestion pipeline; auditing can happen in a Python CI job.
- A TypeScript edge function can verify pins produced by a Python batch processor.
- Backups can be re-verified years later from any implementation that conforms to the v2 spec.

---

## Failure-Mode Reference

| Outcome | Cause | Typical action |
|---|---|---|
| `OK` | Everything checks out. | Proceed. |
| `UNSUPPORTED_VERSION` | `v` is not in this verifier's set. | Upgrade verifier, or re-pin under v2. |
| `UNKNOWN_KEY` | `kid` is not in the registry. | Misconfiguration — add the key. |
| `KEY_EXPIRED` | `ts` is outside the registered `(valid_from, valid_until)`. | Rotation / revocation working as intended. |
| `PARSE_ERROR` | Oversized pin, unknown top-level field, non-string `extra` value, malformed timestamp, non-NFC string, `NaN`/`Inf` in vector. | Reject the pin; likely hostile or buggy producer. |
| `SIGNATURE_INVALID` | Pin forged, signed with the wrong key, or canonicalization differs. | **Security incident.** |
| `VECTOR_TAMPERED` | Stored vector differs from the one originally pinned. | **Security incident.** Likely steganography or DB compromise. |
| `SOURCE_MISMATCH` | Source text differs from what was pinned. | Source-side drift — investigate. |
| `MODEL_MISMATCH` | Pin was produced by a different model than expected. | Ingestion pipeline using wrong model — investigate. |
| `SHAPE_MISMATCH` | Caller's vector has the wrong dimensionality. | Misconfiguration. |
| `RECORD_MISMATCH` / `COLLECTION_MISMATCH` / `TENANT_MISMATCH` | Replay-protection mismatch. | Likely pin-shuffle attack — investigate. |

---

## See Also

- [Specification](spec.md) — Normative v2 wire format
- [Getting Started](getting-started.md) — Pinning and verifying in code
- [Security](security.md) — Threat model and best practices
