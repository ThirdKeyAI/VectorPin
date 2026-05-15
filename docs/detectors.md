# Statistical Detectors

Cryptographic pinning catches **modifications** to vectors after they are produced. Statistical detectors catch a different class of attack: **ingestion-time poisoning**, where a compromised pipeline writes legitimately-signed-but-malicious vectors into the store.

The two are complementary. Pinning is the durable layer; statistical detection is defense-in-depth.

---

## What Pinning Doesn't Catch

A pin attests:

> *"This vector is what the model produced from this source text."*

It does **not** attest:

> *"This vector came from a benign source text."*

If an attacker compromises the ingestion pipeline (or the upstream document corpus) and feeds in:

- Vectors derived from sensitive content the attacker controls
- Vectors crafted to skew RAG retrieval toward attacker-chosen passages
- Vectors that encode exfiltration payloads in the embedding's noise floor before pinning

…then every pin is technically valid. The signature is correct, the hash matches, the vector is intact since pinning. The integrity layer cannot tell that the vector is *suspicious*.

Statistical detectors look at the distribution of vectors over the store and flag anomalies that have no business being there.

---

## Quick Start

Requires the `detectors` extra:

```bash
pip install 'vectorpin[detectors]'
```

```python
from vectorpin.detectors.isolation_forest import IsolationForestDetector

# Fit on a corpus you trust (e.g., before exposing the ingestion pipeline)
detector = IsolationForestDetector().fit(clean_embeddings)

# Score new arrivals
flagged = detector.decide(suspect_embeddings)
# `flagged` is a boolean array — True means "anomalous, hold for review"
```

In the VectorSmuggle empirical study, this single line of defense flagged every operating point of every distribution-shifting steganographic technique that hides a non-trivial amount of data.

---

## What Detectors Catch

| Attack | Pinning catches | Detectors catch |
|---|---|---|
| Modify a vector in the DB | ✅ (`VECTOR_TAMPERED`) | maybe |
| Re-sign with a stolen key | ❌ | maybe |
| Inject new vectors derived from exfil text | ❌ | ✅ |
| Inject vectors with steganographic noise (high payload) | ❌ | ✅ |
| Inject vectors with steganographic noise (low payload) | ❌ | maybe |
| Orthogonal rotation of all vectors | ✅ (`VECTOR_TAMPERED`) | ❌ |
| Replace source documents before embedding | ❌ | maybe |

Detectors and pins overlap on the "modify a vector in the DB" attack — pins always catch it cleanly. But for the four attacks where pinning has a blind spot, detectors fill in some of the gap.

**Detectors are brittle against an adaptive attacker** who knows the detector and can evade it (e.g., projecting their payload onto the in-distribution subspace). Use them as defense-in-depth, not as a primary control.

---

## Available Detectors

### IsolationForestDetector

The default. Wraps `sklearn.ensemble.IsolationForest` with a VectorPin-shaped API.

```python
from vectorpin.detectors.isolation_forest import IsolationForestDetector

detector = IsolationForestDetector(
    n_estimators=100,
    contamination=0.05,   # expected anomaly rate during fit
)
detector.fit(clean_embeddings)

# Bool decision (True = anomaly)
flagged = detector.decide(new_embeddings)

# Continuous anomaly score (higher = more anomalous)
scores = detector.score(new_embeddings)
```

**Strengths:**

- Cheap to fit and score.
- Catches distribution shift in noise injection, scaling, offset perturbation, cross-model fragmentation.

**Weaknesses:**

- Cannot catch orthogonal rotation (preserves every density feature the detector fits on).
- Cannot catch payload that is projected onto the in-distribution subspace.
- Performance depends on the fit corpus being representative of legitimate traffic.

---

## Operational Patterns

### Ingestion-time gate

The strictest pattern: fit a detector once on a trusted corpus, and reject any new embedding it flags before pinning. This means rejected payloads never get a valid pin.

```python
from vectorpin import Signer
from vectorpin.detectors.isolation_forest import IsolationForestDetector

signer = Signer.generate(key_id="prod-2026-05")
detector = IsolationForestDetector().fit(trusted_corpus_embeddings)

def ingest(source: str, vector):
    if detector.decide([vector])[0]:
        raise IngestionRejected(f"vector flagged by detector")
    return signer.pin(source=source, model="text-embedding-3-large", vector=vector)
```

### Periodic re-scoring

Re-run the detector across the live corpus on a cadence (nightly, weekly) and surface newly-flagged records for review. Use this when ingestion is high-volume and the detector is too expensive to run inline.

```python
flagged_ids = []
for record in adapter.iter_records():
    if detector.decide([record.vector])[0]:
        flagged_ids.append(record.id)
```

### Combined with pin audit

The natural CI shape is:

1. Run `vectorpin audit-*` — fails if any pin is broken.
2. Re-score the corpus with a detector fitted on a held-out trusted subset — fails if the anomaly rate jumps.

Step 1 catches modifications; step 2 catches poisoning campaigns.

---

## What Detectors Don't Promise

- **No formal guarantee.** A false-negative is a single rounding decision; an adaptive attacker can target it.
- **No model-specific tuning out of the box.** The default contamination parameter is a starting point — tune against your model and corpus.
- **No multi-tenant separation.** If you fit one detector on a mixed-tenant corpus, you'll see tenant-shift false positives. Fit per-tenant.

For the empirical study underlying the design choices here, see the [VectorSmuggle preprint](https://doi.org/10.5281/zenodo.20058256).

---

## See Also

- [Pin Protocol](pin-protocol.md) — What pinning does guarantee
- [Security](security.md) — Threat model
- [VectorSmuggle](https://github.com/jaschadub/VectorSmuggle) — Companion threat-research project
