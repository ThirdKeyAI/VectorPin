# Deployment Guide

This guide covers how to deploy VectorPin in production: key custody, rotation, CI integration, and the operational patterns that distinguish a real deployment from a demo.

---

## Architecture Overview

```
Ingestion pipeline                Vector store               Audit / verify
──────────────────                ────────────               ──────────────

text + model ─┐                                              ┌─ verifier
              │                                              │  (with key
   signer  ───┼──> (vector, pin) ──> LanceDB / Chroma / ... ─┤   registry)
   (private)  │                                              │
              │                                              └─ result
   KMS / file ┘                                                 (per record)
```

The pin is produced once at ingestion (where the private key lives) and verified continuously at read or audit time (where only the public key lives). This asymmetry is the whole point — verifiers need no secret material.

---

## Key Custody

VectorPin private keys are the only things an attacker needs in order to forge valid pins. Treat them accordingly.

### Filesystem keys (development / small deployments)

The CLI writes raw Ed25519 bytes:

```bash
vectorpin keygen --key-id prod-2026-05 --output ./keys
chmod 600 ./keys/prod-2026-05.priv
```

| Property | Recommendation |
|---|---|
| File permissions | `0600`, owner = signing process user |
| Storage | Encrypted disk; never plaintext in version control |
| Backup | Encrypted, offline, in escrow at your org's secrets-of-record location |
| Distribution | Out of band — never email / chat / paste |

### KMS / HSM (recommended for production)

Production deployments SHOULD use a KMS or hardware-backed signer rather than file-system keys. The signing API can be wrapped — see [`Signer.from_pem`](https://github.com/ThirdKeyAI/VectorPin/blob/main/src/vectorpin/signer.py) for the surface to integrate against.

Typical wrappers:

- AWS KMS asymmetric keys (Ed25519 supported as of 2024).
- GCP Cloud KMS asymmetric keys.
- Azure Key Vault managed keys.
- YubiHSM / Nitrokey HSM for on-prem.

Whatever you use, the only material that should ever leave the boundary is the public key bytes and the 64-byte signature on a specific `signed_bytes`.

### Per-environment separation

Use separate signing keys for separate environments. A staging key compromise must not invalidate production pins.

```
prod-2026-05      # production
staging-2026-05   # staging
dev-2026-05       # local dev
```

Verifier registries SHOULD include only the keys appropriate to that environment — a production verifier should not honor staging-signed pins.

### Per-tenant separation

Multi-tenant deployments SHOULD issue separate `kid`s per tenant rather than share a single producer key. This way, compromise of one tenant's environment cannot forge pins for another tenant.

---

## Verifier Key Registries

A verifier holds a mapping from `kid` to `(public_key, valid_from, valid_until)`. How that registry is populated is out of scope of the protocol, but the following SHOULD hold:

- **Fingerprint format**: Operators identifying a key out of band SHOULD use `SHA-256(pubkey_bytes)` truncated to the first 16 hex digits, formatted as four colon-separated quads — e.g. `1f3a:7b22:9e0d:c4f1`.
- **Transparency log**: Production registries SHOULD reference a transparency-log entry (e.g., sigstore Rekor) for each `kid` registration and revocation. This lets downstream verifiers detect a malicious registry rollback.
- **TOFU is not recommended**: A verifier that auto-registers any `kid` it encounters provides no integrity guarantee — it's a checksum, not a signature.

### Python registry shape

```python
from vectorpin import Verifier, KeyEntry
from datetime import datetime, timezone

verifier = Verifier({
    "prod-2026-05": KeyEntry(
        public_key=load_public_bytes("./keys/prod-2026-05.pub"),
        valid_from=datetime(2026, 5, 1, tzinfo=timezone.utc),
        valid_until=None,   # still current
    ),
    "prod-2025-11": KeyEntry(
        public_key=load_public_bytes("./keys/prod-2025-11.pub"),
        valid_from=datetime(2025, 11, 1, tzinfo=timezone.utc),
        valid_until=datetime(2026, 5, 1, tzinfo=timezone.utc),   # rotated out
    ),
})
```

Pins signed by `prod-2025-11` continue to verify against the registry as long as their `ts` falls in `[2025-11-01, 2026-05-01)`.

---

## Key Rotation

Rotate regularly, even without a known compromise. Suggested cadence:

| Key | Rotation period |
|---|---|
| Production signing keys | Every 6–12 months |
| Staging / dev keys | Every 3 months |
| Keys after suspected compromise | Immediately (see [Revocation](#revocation)) |

### Rotation procedure

1. Generate a new keypair with a fresh `kid` (e.g., `prod-2026-11`).
2. Add the new public key to all verifier registries with `valid_from` no earlier than when the new private key becomes operational. Leave the old key in place.
3. Switch production signing to the new private key.
4. Set `valid_until` on the old key entry to the cutover instant. **Do not delete the old entry** — historical pins must continue to verify against it.
5. Optionally re-pin the corpus over time with the new key. This is not required — old pins remain valid forever within their key's window.

### Revocation

If a private key is compromised, set `valid_until` on the `kid` entry to the latest moment the key is believed to have been uncompromised. Pins with `ts` after that instant return `KEY_EXPIRED`; pins with `ts` before it continue to verify.

The protocol does not specify a revocation file format in v2 — this is intentional, so deployments can integrate with existing PKI / sigstore infrastructure. The minimum requirement on a verifier is to honor the `(valid_from, valid_until)` window, however it is delivered.

Operators SHOULD pair revocation with a transparency-log entry for the revocation event itself, so that downstream verifiers can detect a malicious registry rollback.

---

## CI Integration

The audit commands are designed to drop into CI unchanged. They print a JSON summary on stdout and exit non-zero on any verification failure.

### Cron audit

```bash
#!/usr/bin/env bash
set -euo pipefail

vectorpin audit-lancedb \
  --uri "$VECTOR_DB_URI" \
  --table "$VECTOR_TABLE" \
  --public-key /etc/vectorpin/prod-2026-05.pub \
  --key-id prod-2026-05 \
  --source-column text \
  > /var/log/vectorpin/$(date -u +%Y-%m-%dT%H:%M:%SZ).json
```

A `cron` entry every 15 minutes plus alerting on non-zero exit gives you per-quarter-hour coverage of the corpus with no further integration work.

### GitHub Actions

```yaml
name: VectorPin audit
on:
  schedule:
    - cron: "0 * * * *"
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install 'vectorpin[default]'
      - run: |
          vectorpin audit-lancedb \
            --uri "${{ secrets.VECTOR_DB_URI }}" \
            --table rag-corpus \
            --public-key ./keys/prod-2026-05.pub \
            --key-id prod-2026-05 \
            --source-column text
```

### Treating unpinned records as failures

By default, `unpinned` records do not fail the run (they're useful during partial backfills). To fail closed:

```bash
summary=$(vectorpin audit-lancedb --uri ... --table ... --public-key ... --key-id ...)
echo "$summary"
echo "$summary" | python -c "import json,sys; sys.exit(1 if json.load(sys.stdin)['unpinned'] else 0)"
```

---

## Inline vs Batch Verification

| Pattern | Pin at | Verify at | Pro | Con |
|---|---|---|---|---|
| **Inline verify** | Ingestion | Every read | Strongest guarantee — no tampered vector ever reaches a model. | Adds ~50–100 µs of CPU per retrieval. |
| **Batch audit** | Ingestion | CI / cron | Zero read-path overhead. | Tampering only detected at next audit. |
| **Hybrid** | Ingestion | Sample reads + CI | Cheap probabilistic coverage. | Tuning required. |

Inline verify on every retrieval is the right default for security-critical workloads (medical RAG, agent runtimes like Symbiont). Batch audit alone is acceptable for lower-stakes RAG when audit cadence is tight (every few minutes). Hybrid suits cost-sensitive deployments that want some inline protection without paying for it on every read.

Sub-millisecond verification latency means inline is rarely the bottleneck.

---

## Performance Budget

Indicative numbers on a modern x86_64 laptop, 3072-dim vectors (`text-embedding-3-large`):

| Operation | Rust (µs) | Python (µs) |
|---|---|---|
| `hash_vector` | 6.4 | 5.8 |
| `sign` (pin) | 35 | 35 |
| `verify_full` | 42 | 79 |
| `verify_signature_only` | 22 | 75 |

Re-run on your own hardware before quoting numbers — see [`scripts/bench_python.py`](https://github.com/ThirdKeyAI/VectorPin/blob/main/scripts/bench_python.py) and [`rust/vectorpin/benches/perf.rs`](https://github.com/ThirdKeyAI/VectorPin/blob/main/rust/vectorpin/benches/perf.rs).

For a 1 M record corpus, a full Python audit completes in roughly 80 seconds of pure VectorPin work (verification only; iterating the backend is separate).

---

## Symbiont Integration

For [Symbiont](https://github.com/ThirdKeyAI/Symbiont) deployments:

- Symbiont's default vector backend is LanceDB; use `LanceDBAdapter` directly.
- Symbiont's source text is in the `content` column. Symbiont's column literally named `source` is upstream provenance like a URL, **not** VectorPin's `source` argument.
- Pass `source=record.metadata["content"]` when calling `signer.pin`.
- See [`tests/test_adapter_lancedb_symbiont.py`](https://github.com/ThirdKeyAI/VectorPin/blob/main/tests/test_adapter_lancedb_symbiont.py) for an end-to-end example against the Symbiont schema.

The Symbiont runtime consumes VectorPin attestations to enforce policy along the lines of "agents may only retrieve from verified vector stores."

---

## See Also

- [Security](security.md) — Threat model and broader best practices
- [CLI Guide](cli-guide.md) — `vectorpin audit-*` reference
- [Pin Protocol](pin-protocol.md#key-rotation-and-revocation) — Protocol-level rotation semantics
