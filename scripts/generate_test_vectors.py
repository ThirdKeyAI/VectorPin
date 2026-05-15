#!/usr/bin/env python3
# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Generate cross-language test vectors for VectorPin protocol v2.

Every language port (Rust, TypeScript) consumes the JSON fixtures this
script writes and asserts that:

  - Recomputing canonical bytes / hashes matches.
  - Signature verification succeeds against the published public key.
  - Negative cases fail with the correct error code from the spec §5
    failure list.

The fixtures use a deterministic signing key seed so output is
reproducible byte-for-byte across runs. The seed and key id are NOT
secrets — they exist solely to make the fixtures verifiable across
implementations.

DETERMINISTIC SEED: bytes(range(32)) — i.e. 0x00..0x1f. Do NOT change
this seed without bumping every cross-language compat test.

Run from the repo root:

    python scripts/generate_test_vectors.py

Outputs v2.json + negative_v2.json under testvectors/. The legacy v1
fixtures (v1.json, negative_v1.json) are deliberately left untouched —
they remain the contract for the opt-in LegacyV1Verifier.
"""

from __future__ import annotations

import base64
import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from vectorpin import (
    DOMAIN_TAG,
    PROTOCOL_VERSION,
    Pin,
    Signer,
)

OUT_DIR = Path(__file__).resolve().parent.parent / "testvectors"

# ---- deterministic key material ----

DETERMINISTIC_SEED = bytes(range(32))  # 0x00..0x1f
KEY_ID = "test-vectors-v2-2026-05"

# Fixed timestamp so signatures are bit-for-bit reproducible.
FIXED_TS = datetime(2026, 5, 5, 12, 0, 0, tzinfo=UTC)
FIXED_TS_ISO = "2026-05-05T12:00:00Z"


def b64url(data: bytes) -> str:
    """URL-safe base64, no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def make_vector(seed: int, dim: int, dtype: str) -> np.ndarray:
    """Reproducible vector. The same (seed, dim, dtype) always yields
    the same byte sequence across machines and Python versions."""
    rng = np.random.default_rng(seed)
    arr = rng.normal(0, 1, size=dim)
    return arr.astype(np.float32 if dtype == "f32" else np.float64)


def vec_canonical_bytes(vec: np.ndarray, dtype: str) -> bytes:
    target = "<f4" if dtype == "f32" else "<f8"
    return vec.astype(target).tobytes()


def _fixture(
    *,
    name: str,
    description: str,
    source: str,
    model: str,
    vec: np.ndarray,
    dtype: str,
    pin: Pin,
) -> dict:
    return {
        "name": name,
        "description": description,
        "input": {
            "source": source,
            "model": model,
            "vec_b64": b64url(vec_canonical_bytes(vec, dtype)),
            "vec_dtype": dtype,
            "vec_dim": int(vec.shape[0]),
            "timestamp": FIXED_TS_ISO,
        },
        "pin_json": pin.to_json(),
        "expected_canonical_bytes_b64": b64url(pin.header.canonicalize()),
        "expected_vec_hash": pin.header.vec_hash,
        "expected_source_hash": pin.header.source_hash,
    }


def build_positive_fixtures(signer: Signer) -> list[dict]:
    fixtures: list[dict] = []

    # 1. Small f32.
    vec = make_vector(seed=0, dim=16, dtype="f32")
    pin = signer.pin(
        source="hello world",
        model="test-model-v1",
        vector=vec,
        vec_dtype="f32",
        timestamp=FIXED_TS,
    )
    fixtures.append(
        _fixture(
            name="vector_0_f32_small",
            description="Small f32 vector, no extras, no model_hash.",
            source="hello world",
            model="test-model-v1",
            vec=vec,
            dtype="f32",
            pin=pin,
        )
    )

    # 2. Small f64.
    vec = make_vector(seed=1, dim=8, dtype="f64")
    pin = signer.pin(
        source="multi\nline\ntext",
        model="test-model-v1",
        vector=vec,
        vec_dtype="f64",
        timestamp=FIXED_TS,
    )
    fixtures.append(
        _fixture(
            name="vector_1_f64_small",
            description="Small f64 vector with multi-line source.",
            source="multi\nline\ntext",
            model="test-model-v1",
            vec=vec,
            dtype="f64",
            pin=pin,
        )
    )

    # 3. With model_hash.
    vec = make_vector(seed=2, dim=32, dtype="f32")
    model_hash = "sha256:" + "a" * 64
    pin = signer.pin(
        source="The quick brown fox jumps over the lazy dog.",
        model="text-embedding-3-large",
        vector=vec,
        vec_dtype="f32",
        model_hash=model_hash,
        timestamp=FIXED_TS,
    )
    f = _fixture(
        name="vector_2_with_model_hash",
        description=(
            "f32 vector with optional model_hash committed under "
            "the signature. Verifiers reconstruct the signed bytes "
            "with model_hash included."
        ),
        source="The quick brown fox jumps over the lazy dog.",
        model="text-embedding-3-large",
        vec=vec,
        dtype="f32",
        pin=pin,
    )
    f["input"]["model_hash"] = model_hash
    fixtures.append(f)

    # 4. With extra (including a reserved replay-protection key).
    vec = make_vector(seed=3, dim=16, dtype="f32")
    extra = {
        "region": "us-west",
        "vectorpin.record_id": "rec-2026-05-05-001",
    }
    pin = signer.pin(
        source="café",
        model="unicode-model",
        vector=vec,
        vec_dtype="f32",
        timestamp=FIXED_TS,
        extra=extra,
    )
    f = _fixture(
        name="vector_3_with_extra_and_record_id",
        description=(
            "f32 vector with a free-form extra entry plus the reserved "
            "vectorpin.record_id replay-protection key. Source is "
            "NFC-normalized Unicode ('café')."
        ),
        source="café",
        model="unicode-model",
        vec=vec,
        dtype="f32",
        pin=pin,
    )
    f["input"]["extra"] = extra
    fixtures.append(f)

    return fixtures


def build_negative_fixtures(signer: Signer, base_pin: Pin, base_vec: np.ndarray) -> list[dict]:
    """One fixture per failure mode listed in spec §5 / task spec."""

    fixtures: list[dict] = []
    base_json = base_pin.to_json()
    base_dict = json.loads(base_json)

    def _emit(name: str, *, description: str, expected_failure: str, **extra_fields):
        fixtures.append(
            {
                "name": name,
                "description": description,
                "expected_failure": expected_failure,
                **extra_fields,
            }
        )

    # a. Tampered f32 vector — vector bytes differ from the pin's vec_hash.
    tampered = base_vec.copy()
    tampered[0] += 1e-3
    _emit(
        "tampered_vector",
        description="The vector bytes have been modified after pinning.",
        expected_failure="VECTOR_TAMPERED",
        pin_json=base_json,
        tampered_vec_b64=b64url(vec_canonical_bytes(tampered, "f32")),
        vec_dtype="f32",
        vec_dim=int(base_vec.shape[0]),
    )

    # b. Tampered source — caller supplies a different source than what was signed.
    _emit(
        "tampered_source",
        description=(
            "The caller supplies a source string that does not match the pin's source_hash."
        ),
        expected_failure="SOURCE_MISMATCH",
        pin_json=base_json,
        tampered_source="goodbye world",
        original_source="hello world",
    )

    # c. Wrong expected_model — caller asks for a different model name.
    _emit(
        "wrong_expected_model",
        description="Caller asks the verifier to enforce a model name that does not match.",
        expected_failure="MODEL_MISMATCH",
        pin_json=base_json,
        expected_model="some-other-model",
    )

    # d. Wrong vec_dim — flipping vec_dim breaks the signature because it's signed.
    d_dict = copy.deepcopy(base_dict)
    d_dict["vec_dim"] = 17  # was 16
    _emit(
        "wrong_vec_dim_breaks_signature",
        description=(
            "vec_dim is part of the signed canonical bytes; changing it "
            "breaks the ed25519 signature verification (not a SHAPE_MISMATCH "
            "because the verifier reaches signature check first)."
        ),
        expected_failure="SIGNATURE_INVALID",
        pin_json=json.dumps(d_dict, sort_keys=True, separators=(",", ":")),
    )

    # e. Wrong v — UNSUPPORTED_VERSION (regardless of signature).
    e_dict = copy.deepcopy(base_dict)
    e_dict["v"] = 99
    _emit(
        "wrong_version",
        description="Pin with v=99; strict v2 verifier rejects before signature check.",
        expected_failure="UNSUPPORTED_VERSION",
        pin_json=json.dumps(e_dict, sort_keys=True, separators=(",", ":")),
    )

    # f. Wrong kid — UNKNOWN_KEY when registry doesn't have it.
    # We deliberately re-sign the pin under the original key but with kid
    # swapped in the JSON. The signature decodes fine but the verifier
    # gates on UNKNOWN_KEY before signature verification (§5 step 2).
    f_dict = copy.deepcopy(base_dict)
    f_dict["kid"] = "no-such-kid"
    _emit(
        "wrong_kid_unknown_key",
        description=(
            "Pin's kid is not in the verifier's registry. UNKNOWN_KEY "
            "fires before signature check per spec §5 step 2."
        ),
        expected_failure="UNKNOWN_KEY",
        pin_json=json.dumps(f_dict, sort_keys=True, separators=(",", ":")),
    )

    # g. Sig bit-flipped — same length, but invalid signature.
    sig_bytes = bytearray(base_pin.sig)
    sig_bytes[0] ^= 0x01
    g_dict = copy.deepcopy(base_dict)
    g_dict["sig"] = b64url(bytes(sig_bytes))
    _emit(
        "sig_bit_flipped",
        description="One bit of the signature has been flipped; ed25519 rejects.",
        expected_failure="SIGNATURE_INVALID",
        pin_json=json.dumps(g_dict, sort_keys=True, separators=(",", ":")),
    )

    # h. Sig wrong length — decodes to 32 bytes instead of 64.
    h_dict = copy.deepcopy(base_dict)
    h_dict["sig"] = b64url(b"\x00" * 32)
    _emit(
        "sig_wrong_length",
        description="Signature decodes to 32 bytes; parser rejects before crypto.",
        expected_failure="PARSE_ERROR",
        pin_json=json.dumps(h_dict, sort_keys=True, separators=(",", ":")),
    )

    # i. Unknown top-level key.
    i_dict = copy.deepcopy(base_dict)
    i_dict["sig2"] = "extra"
    _emit(
        "unknown_top_level_field",
        description="Pin contains a top-level field outside the v2 allowed set.",
        expected_failure="PARSE_ERROR",
        pin_json=json.dumps(i_dict, sort_keys=True, separators=(",", ":")),
    )

    # j. Non-string extra value.
    j_dict = copy.deepcopy(base_dict)
    j_dict["extra"] = {"region": 5}
    _emit(
        "non_string_extra_value",
        description="extra map contains a value that is not a string.",
        expected_failure="PARSE_ERROR",
        pin_json=json.dumps(j_dict, sort_keys=True, separators=(",", ":")),
    )

    # k. NaN in vector at verify time.
    nan_vec = base_vec.copy().astype(np.float32)
    nan_vec[0] = float("nan")
    _emit(
        "nan_in_vector_at_verify",
        description=(
            "Caller supplies a vector containing NaN. Verifier rejects "
            "before hashing per spec §5 step 6."
        ),
        expected_failure="PARSE_ERROR",
        pin_json=base_json,
        # Manually serialize the NaN-bearing bytes; JSON doesn't allow
        # NaN, so we encode as raw little-endian f32 bytes via b64.
        nan_vec_b64=b64url(nan_vec.tobytes()),
        vec_dtype="f32",
        vec_dim=int(base_vec.shape[0]),
    )

    # l. NFD source string in model field — non-NFC strings are rejected.
    # We construct NFD explicitly from code points so the distinction
    # survives editor normalization: 'cafe' + U+0301 COMBINING ACUTE
    # ACCENT is the NFD form of 'café' (which in NFC is U+00E9).
    nfd_model = "cafe\u0301"
    assert nfd_model != "caf\u00e9", "NFD/NFC distinction collapsed"
    nfd_dict = copy.deepcopy(base_dict)
    nfd_dict["model"] = nfd_model
    _emit(
        "nfd_model_string",
        description=(
            "model field is in NFD form ('café' as e + COMBINING ACUTE), "
            "not NFC. Parser rejects per spec §3.1."
        ),
        expected_failure="PARSE_ERROR",
        pin_json=json.dumps(nfd_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
    )

    # m. Timestamp with fractional seconds.
    m_dict = copy.deepcopy(base_dict)
    m_dict["ts"] = "2026-05-05T12:00:00.000Z"
    _emit(
        "ts_fractional_seconds",
        description="Timestamp has fractional seconds; strict regex rejects.",
        expected_failure="PARSE_ERROR",
        pin_json=json.dumps(m_dict, sort_keys=True, separators=(",", ":")),
    )

    # n. Timestamp with offset.
    n_dict = copy.deepcopy(base_dict)
    n_dict["ts"] = "2026-05-05T12:00:00+00:00"
    _emit(
        "ts_with_offset",
        description="Timestamp has an explicit offset instead of trailing Z.",
        expected_failure="PARSE_ERROR",
        pin_json=json.dumps(n_dict, sort_keys=True, separators=(",", ":")),
    )

    # o. Timestamp with lowercase t / z.
    o_dict = copy.deepcopy(base_dict)
    o_dict["ts"] = "2026-05-05t12:00:00z"
    _emit(
        "ts_lowercase_tz",
        description="Timestamp uses lowercase t/z separators; strict regex rejects.",
        expected_failure="PARSE_ERROR",
        pin_json=json.dumps(o_dict, sort_keys=True, separators=(",", ":")),
    )

    # p. RECORD_MISMATCH — pin has a record_id, caller expects a different one.
    p_signer = Signer.from_private_bytes(DETERMINISTIC_SEED, key_id=KEY_ID)
    p_pin = p_signer.pin(
        source="hello world",
        model="test-model-v1",
        vector=base_vec,
        vec_dtype="f32",
        timestamp=FIXED_TS,
        extra={"vectorpin.record_id": "rec-real"},
    )
    _emit(
        "record_id_mismatch",
        description=(
            "Pin commits to vectorpin.record_id=rec-real but the caller "
            "asks the verifier to enforce rec-other."
        ),
        expected_failure="RECORD_MISMATCH",
        pin_json=p_pin.to_json(),
        expected_record_id="rec-other",
    )

    # q. Oversize pin JSON — synthetic 70 KiB.
    q_dict = copy.deepcopy(base_dict)
    # Pad sig field with a long base64-looking string. The parser rejects
    # on raw byte length before any structural check.
    q_dict["model"] = "x" * 70_000
    _emit(
        "oversize_pin_json",
        description="Pin JSON exceeds the §4.3 64 KiB cap; rejected pre-parse.",
        expected_failure="PARSE_ERROR",
        pin_json=json.dumps(q_dict, sort_keys=True, separators=(",", ":")),
    )

    return fixtures


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    signer = Signer.from_private_bytes(DETERMINISTIC_SEED, key_id=KEY_ID)

    # ---- positive fixtures ----
    fixtures = build_positive_fixtures(signer)

    out = {
        "version": PROTOCOL_VERSION,
        "domain_tag_b64": b64url(DOMAIN_TAG),
        "comment": (
            "Cross-language test vectors for VectorPin protocol v2. "
            "The signing key seed is intentionally public — it exists "
            "only to make these fixtures reproducible. Do not use in "
            "production."
        ),
        "key_id": KEY_ID,
        "public_key_b64": b64url(signer.public_key_bytes()),
        "private_key_b64": b64url(DETERMINISTIC_SEED),
        "fixtures": fixtures,
    }

    positive_path = OUT_DIR / "v2.json"
    positive_path.write_text(json.dumps(out, indent=2) + "\n")

    # ---- negative fixtures ----
    # Use the first positive fixture as the base for negatives so each
    # has a real, well-formed pin to tamper with.
    base_vec = make_vector(seed=0, dim=16, dtype="f32")
    base_pin = signer.pin(
        source="hello world",
        model="test-model-v1",
        vector=base_vec,
        vec_dtype="f32",
        timestamp=FIXED_TS,
    )
    negatives = build_negative_fixtures(signer, base_pin, base_vec)

    negative_out = {
        "version": PROTOCOL_VERSION,
        "comment": (
            "Negative-case test vectors for VectorPin protocol v2. "
            "Each entry's `expected_failure` matches one of the v2 "
            "VerifyError codes from spec §5."
        ),
        "key_id": KEY_ID,
        "public_key_b64": b64url(signer.public_key_bytes()),
        "private_key_b64": b64url(DETERMINISTIC_SEED),
        "fixtures": negatives,
    }
    negative_path = OUT_DIR / "negative_v2.json"
    negative_path.write_text(json.dumps(negative_out, indent=2) + "\n")

    print(f"wrote {positive_path}")
    print(f"wrote {negative_path}")
    print(f"  positive fixtures: {len(fixtures)}")
    print(f"  negative fixtures: {len(negatives)}")


if __name__ == "__main__":
    main()
