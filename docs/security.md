# Security Best Practices

This guide covers the security model, threat mitigations, and operational best practices for VectorPin deployments.

---

## Cryptographic Foundation

VectorPin uses **Ed25519** signatures and **SHA-256** hashing exclusively. All other algorithms are rejected.

| Property | Value |
|----------|-------|
| Signature algorithm | Ed25519 (RFC 8032) |
| Hash algorithm | SHA-256 |
| Domain separator | exact ASCII bytes `vectorpin/v2\x00` (13 bytes) |
| Signature encoding | URL-safe base64, no padding (64 decoded bytes) |
| Pin format | JSON, canonicalized per spec §4.2 |

### Why a single algorithm

Single-algorithm enforcement prevents:

- **Algorithm confusion attacks** — Attacker substitutes `none` or a weak HMAC variant to bypass verification. (VectorPin signatures are raw Ed25519, not JWT-shaped — but the principle still applies: there is no algorithm field to confuse.)
- **Downgrade attacks** — Attacker forces a weaker algorithm. The protocol version `v` is part of the signed payload (§4.2 of the spec), so a v2 verifier cannot be tricked into validating a v1-style signature on a v2 pin.
- **Implementation complexity** — Fewer code paths means fewer bugs.

All three implementations (Python, Rust, TypeScript) bind the algorithm and the protocol version into the canonical bytes via the `vectorpin/v2\x00` domain tag before any signature operation.

---

## Threat Model

VectorPin is designed against an attacker who can:

- ✅ **Modify vectors after they are produced** — via a poisoned ingestion pipeline, a compromised vector DB, or backup-level access. This is the steganography attack class from [VectorSmuggle](https://github.com/jaschadub/VectorSmuggle). VectorPin catches this with `VECTOR_TAMPERED`.
- ✅ **See the public verification key**, but not the private signing key. Ed25519 public-key recovery is computationally infeasible.
- ✅ **Replay or selectively delete pins** within a corpus — partly mitigated via `vectorpin.record_id` / `vectorpin.collection_id` / `vectorpin.tenant_id` in `extra` (see [Replay Protection](#replay-protection)).
- ✅ **Strip new fields and present a downgraded pin** — defeated by `v` and `kid` being in the signed canonical bytes, plus strict rejection of unknown top-level fields.
- ✅ **Reuse a signature against a sister Trust-Stack protocol** — defeated by the 13-byte `vectorpin/v2\x00` domain separator.

VectorPin does **not** defend against:

- ❌ **An attacker with the private signing key.** Out of scope; key custody is the user's responsibility. See [Key Custody](deployment.md#key-custody).
- ❌ **An attacker who modifies source documents *before* embedding.** Pair with upstream content integrity controls (signed ingestion logs, document provenance).
- ❌ **An attacker who uses a legitimate signing key to attest a malicious vector at ingestion time.** Pair with upstream input validation; see [Statistical Detectors](detectors.md) for defense-in-depth.
- ❌ **Cross-record replay within a corpus** unless the caller uses `vectorpin.record_id` and verifies it.

---

## Key Management

### Private Key Security

- **Never commit private keys** to version control.
- **Never embed private keys** in application code or environment variables in plaintext.
- Store private keys in secure storage: file system with restricted permissions, a KMS, or an HSM.
- Use separate keys for separate environments (dev, staging, production).
- Use separate keys for separate tenants in multi-tenant deployments.

```bash
# Set restrictive permissions on private key files
chmod 600 ./keys/*.priv

# Verify
ls -la ./keys/*.priv
# -rw------- 1 vectorpin vectorpin 32 May 15 2026 prod-2026-05.priv
```

Production deployments SHOULD use a KMS or hardware-backed signer. See [Deployment > Key Custody](deployment.md#key-custody).

### Key Rotation

Rotate keys on a schedule, even without a known compromise:

| Key Type | Rotation Period |
|----------|----------------|
| Production signing keys | Every 6–12 months |
| Development / testing keys | Every 3 months |
| Keys after suspected compromise | Immediately |

The rotation procedure leaves historical pins valid forever — see [Deployment > Key Rotation](deployment.md#key-rotation) for the step-by-step.

### Key ID Naming Convention

Use descriptive, time-stamped key IDs for traceability:

```
{purpose}-{year}-{sequence}

Examples:
  prod-2026-05        # production, May 2026
  prod-2026-11        # production, November 2026 (after rotation)
  staging-2026-05     # staging environment
  tenant-acme-2026-05 # per-tenant key
```

### Key Fingerprints

When identifying a key out of band (Slack, email, ticket), use a 16-hex-digit fingerprint of the public key:

```
fingerprint(pub) := SHA-256(pub)[:8] formatted as four colon-separated quads

Example: 1f3a:7b22:9e0d:c4f1
```

This is short enough to read over a phone, long enough to make collisions infeasible.

---

## Operational Practices

### Verifier Hygiene

- **Always pin verifiers to a fixed key registry.** Do not enable TOFU for new pins unless you've explicitly weighed the tradeoff — auto-registering any `kid` you see makes the system a checksum, not a signature.
- **Honor the `(valid_from, valid_until)` window strictly.** This is how both rotation and revocation work.
- **Reject unknown top-level fields.** This is a verifier MUST in the v2 spec; it defeats downgrade attacks.
- **Enforce size limits before parsing the signature.** A single hostile pin without the §4.3 limits can exhaust verifier resources.

### Storage Hygiene

- Store pins under the metadata key `vectorpin` (the protocol convention).
- Back up your pins along with your vectors — a pin without its vector is useless, and vice versa.
- For cold backups, also store a copy of the public-key registry and `(valid_from, valid_until)` windows in effect at backup time, so you can verify the backup years later.

### Replay Protection

Pins are not bound to a specific record id at the wire-format level. An attacker who copies a pin from record A to record B can pass verification only if the vector and source they paste alongside also match. In a corpus of near-duplicates, that's a real concern.

Set the reserved `extra` keys at pin time:

```python
pin = signer.pin(
    source=record_text,
    model="text-embedding-3-large",
    vector=record_vector,
    extra={
        "vectorpin.collection_id": "rag-corpus",
        "vectorpin.record_id": record_id,
        "vectorpin.tenant_id": tenant_id,
    },
)
```

And verify them:

```python
result = verifier.verify(
    pin,
    source=record_text,
    vector=record_vector,
    expected_record_id=record_id,
    expected_collection_id="rag-corpus",
    expected_tenant_id=tenant_id,
)
```

Every `extra` entry is signed, so the values are tamper-evident. Verifiers MUST enforce them when the caller supplies an expected value.

The `vectorpin.` prefix is reserved for this specification — do not use it for your own keys.

### Source-Time Integrity

VectorPin attests to the relationship between source and vector **at pin time**. It does not attest that the source itself was authentic at ingestion. If the upstream document corpus is mutable, an attacker who controls it can have a legitimately-signed pin still mean something different than what you expect.

Pair VectorPin with source-side controls where this matters:

- Signed ingestion logs (e.g., sigstore Rekor entry per ingested document).
- Document provenance metadata captured at the moment of ingestion.
- Source hashing on the upstream document, separate from the embedding.

---

## Defense in Depth

VectorPin alone is the cryptographic backstop for vector integrity. For a hardened deployment, layer it:

| Layer | What it catches |
|---|---|
| **Source integrity** (upstream) | Tampering with documents *before* embedding. |
| **Input validation** (ingestion) | Out-of-policy content that would otherwise be embedded and pinned. |
| **Statistical detectors** ([details](detectors.md)) | Ingestion-time poisoning that passes input validation. |
| **VectorPin** | Any modification of a vector after it is pinned. |
| **Inline verification at retrieval** | Catches DB-level tampering before any model consumes a vector. |
| **Periodic audit** ([details](deployment.md#ci-integration)) | Backstop for the read-path verifier. |
| **Transparency log** (sigstore Rekor) | Detects registry rollback or undisclosed key revocation. |

The cryptographic guarantee from VectorPin survives every layer above it being compromised, as long as the private key is safe.

---

## Reporting Vulnerabilities

For security-sensitive findings, email `security@thirdkey.ai` rather than filing public issues. Do not disclose details in GitHub issues, social media, or talks until a fix has shipped to all three implementations.

---

## See Also

- [Pin Protocol](pin-protocol.md) — How verification is structured
- [Deployment](deployment.md) — Key custody and rotation in practice
- [Detectors](detectors.md) — Statistical defense-in-depth
- [Specification §9](spec.md#9-security-considerations) — Normative security considerations
