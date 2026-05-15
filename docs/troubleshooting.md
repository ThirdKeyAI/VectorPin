# Troubleshooting

Common issues and solutions when working with VectorPin.

---

## Verification Errors

### `VECTOR_TAMPERED`

**Problem:** The vector hash does not match `vec_hash`.

```
FAIL [vector_tampered] vec_hash mismatch
```

**Cause:** The stored vector differs from the one originally pinned. This is the steganography kill shot — it is what VectorPin exists to catch. Treat as a security incident until proven otherwise.

**Triage steps:**

1. Confirm you're passing the **stored** vector (not a re-computed one) to `verify()`.
2. Check for `f32` vs `f64` dtype mismatch between pin time and verify time. The pin commits to a specific `vec_dtype`; converting before hashing breaks the hash.
3. Check for FTZ/DAZ floating-point modes. Disable them, or normalize subnormals to zero before hashing.
4. If 1–3 are clean, treat as a real integrity failure. Pull backups, investigate write paths, and rotate any keys whose `valid_until` window covers the affected pins.

---

### `SOURCE_MISMATCH`

**Problem:** The source-text hash does not match `source_hash`.

```
FAIL [source_mismatch] source_hash mismatch
```

**Common causes:**

1. **Encoding drift** — Source text was UTF-16 / Latin-1 at one site, UTF-8 at the other.
2. **Whitespace drift** — Trailing newline added or stripped; line endings normalized.
3. **Unicode normalization** — Text was not NFC-normalized before pinning. (VectorPin always NFC-normalizes; the failure means the input was different.)
4. **Wrong source column** — On Symbiont, `content` holds the text the embedding was produced from; `source` holds a URL. Using the wrong column breaks the hash. See [Adapters > Symbiont schema](adapters.md#symbiont-schema).

**Solution:** Match the exact bytes the embedding was produced from. The pin commits to NFC-normalized UTF-8 of the source string passed to `signer.pin`.

---

### `MODEL_MISMATCH`

**Problem:** The pin's `model` field differs from the caller's expected model.

```
FAIL [model_mismatch] model "text-embedding-3-small" != expected "text-embedding-3-large"
```

**Cause:** The pin was produced with a different embedding model than the verifier expects.

**Solution:** Either the ingestion pipeline used the wrong model, or the verifier was configured with the wrong expectation. Confirm which is correct, then either re-pin or update the verifier config.

This check only fires when the caller passes an `expected_model` argument. If you don't supply one, model mismatch is silently accepted (the source/vector hashes still have to match, so this is only a confidentiality leak about which model the producer used — not an integrity failure).

---

### `UNKNOWN_KEY`

**Problem:** The pin's `kid` is not in the verifier's registry.

```
FAIL [unknown_key] kid "prod-2026-05" not in registry
```

**Common causes:**

1. **Misconfiguration** — Verifier wasn't given the public key for this `kid`.
2. **Cross-environment leak** — A pin from staging reached production (or vice versa).
3. **Forged `kid`** — Less likely, since `kid` is in the signed canonical bytes (§4.2). If `kid` was tampered with, you'd see `SIGNATURE_INVALID` first.

**Solution:** Add the missing public key to the registry, **after** confirming the key fingerprint out of band:

```python
verifier = Verifier({
    "prod-2026-05": load_public_bytes("./keys/prod-2026-05.pub"),
    # add the missing one:
    "prod-2025-11": load_public_bytes("./keys/prod-2025-11.pub"),
})
```

**Do not** silently auto-register unknown keys (TOFU). That makes the system a checksum, not a signature.

---

### `KEY_EXPIRED`

**Problem:** The pin's `ts` falls outside the registered key's `(valid_from, valid_until)` window.

```
FAIL [key_expired] ts 2026-06-01T00:00:00Z is after valid_until 2026-05-15T12:00:00Z
```

**Cause:** Either the key was rotated (and the new key is what should have signed this pin) or the key was revoked due to compromise.

**Solution:**

- If the pin's `ts` is recent and the producer should still be signing with this key — the registry's `valid_until` is wrong. Fix the window.
- If `valid_until` is correct and the pin is supposed to be there — the pin is suspect. It was signed after the key was retired, which means either clock skew on the producer or a real compromise. Investigate.
- If the key was deliberately revoked due to compromise, this is the system working as designed.

See [Pin Protocol > Key Rotation and Revocation](pin-protocol.md#key-rotation-and-revocation).

---

### `SIGNATURE_INVALID`

**Problem:** The Ed25519 signature does not validate against the registered public key.

```
FAIL [signature_invalid] signature verification failed
```

**Triage steps:**

1. Confirm the public key bytes match the private key that produced the pin. (Public-key fingerprint mismatch = wrong key in the registry.)
2. Confirm both implementations are on the same protocol version. A v1 pin presented to a strict v2 verifier produces `UNSUPPORTED_VERSION`, not `SIGNATURE_INVALID` — but a v2 pin whose canonical bytes were reconstructed wrongly will fail signature.
3. Check for double-decoding of the pin JSON (e.g., the JSON was JSON-decoded twice and is now a string-of-a-string).

If 1–3 are clean and the failure is consistent, treat as a security incident — someone produced a pin with a key that isn't yours.

---

### `SHAPE_MISMATCH`

**Problem:** The caller's vector has a different dimensionality than `vec_dim`.

```
FAIL [shape_mismatch] vector has dim 1536, pin has vec_dim 3072
```

**Cause:** Wrong embedding model on either side, or wrong vector field plucked from the DB record.

**Solution:** Confirm the vector being passed to `verify()` is the one from the same record as the pin, and that both sides agree on the embedding model.

---

### `UNSUPPORTED_VERSION`

**Problem:** The pin's `v` is not in the verifier's supported set.

```
FAIL [unsupported_version] v=1, only v=2 supported
```

**Cause:** A v1 pin from before the May 2026 wire-format break. v1 is not backwards-compatible with v2.

**Solution:** Re-pin the affected records using a v2 signer. If you need to verify v1 pins for a migration, use `LegacyV1Verifier` (opt-in only). See [Specification §12](spec.md#12-changes-from-v1) for the v1 → v2 change list.

---

### `PARSE_ERROR`

**Problem:** The pin JSON is malformed, oversized, or contains disallowed content.

```
FAIL [parse_error] unknown top-level field: "foo"
FAIL [parse_error] string field "model" is not NFC-normalized
FAIL [parse_error] pin exceeds 64 KiB size limit
```

**Common causes:**

1. **Unknown top-level fields** — v2 verifiers MUST reject them. This is a downgrade-attack defense.
2. **Non-string `extra` values** — `extra` is strictly `map<string, string>`.
3. **Non-NFC strings** — every string field must be NFC-normalized.
4. **Control characters or bidi overrides** in strings — always rejected.
5. **Oversized pin** — exceeds the 64 KiB limit, or `extra` exceeds 32 entries.
6. **Malformed timestamp** — `ts` must match exactly `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`. No fractional seconds, no timezone offsets, no lowercase `t`/`z`.

**Solution:** Inspect the failing pin. Most `PARSE_ERROR` cases are buggy producers — fix the producer, re-pin. Hostile pins go to your security log.

---

### `RECORD_MISMATCH` / `COLLECTION_MISMATCH` / `TENANT_MISMATCH`

**Problem:** Replay-protection check failed.

```
FAIL [record_mismatch] expected record_id "doc-123", pin attests "doc-456"
```

**Cause:** A pin from record A was attached to record B, then audited with the expected record id for B. This is exactly what the reserved `vectorpin.record_id` (etc.) keys are designed to catch — see [Security > Replay Protection](security.md#replay-protection).

**Solution:** Investigate as a possible pin-shuffle attack. If it's a legitimate copy / re-keying operation, re-pin under the new record id.

---

## Pinning Errors

### `vector contains NaN` / `vector contains Inf`

**Problem:** The vector contains `NaN`, `+Inf`, or `-Inf`.

**Cause:** Numerical issue upstream of pinning — e.g., a model that produced NaN for an empty or degenerate input.

**Solution:** Reject the embedding upstream, don't try to pin it. Pinning NaN/Inf is forbidden by the protocol because their canonical byte representation isn't unique enough across implementations.

---

### `string field is not NFC-normalized`

**Problem:** A string field (source, model, kid, an `extra` key/value) is not NFC.

**Solution:** Normalize before passing to `signer.pin`. The signer also normalizes, but it rejects strings containing control characters or bidi overrides outright.

---

### Vector dtype confusion

If you sign with `f32` but verify with the same array cast to `f64`, the hashes differ. The pin's `vec_dtype` is authoritative — verifiers cast the supplied vector to that dtype before hashing. Make sure your storage and your signing path agree on the dtype.

---

## Adapter Errors

### LanceDB: `column 'text' not found`

**Problem:** `--source-column text` (or the programmatic equivalent) names a column that doesn't exist on the table.

**Solution:** Check the table schema. On Symbiont, the source text lives in `content`, not `text`. Pass `--source-column content`.

### Chroma: `audit-chroma requires either --path or --host`

**Solution:** Pick one. `--path /path/to/db` for `PersistentClient`, `--host chroma.host --port 8000` for HTTP.

### Qdrant: pin not visible in payload

**Problem:** Pins were attached, but `audit-qdrant` reports them as `unpinned`.

**Cause:** The pin is stored under `payload["vectorpin"]`. If your write path uses `set_payload` with a partial dict, ensure the dict actually includes that key.

---

## See Also

- [Pin Protocol > Failure-Mode Reference](pin-protocol.md#failure-mode-reference) — One-line summary of every error
- [Security](security.md) — When to escalate, when to fix config
- [Getting Started](getting-started.md) — Sanity-check end-to-end walkthrough
