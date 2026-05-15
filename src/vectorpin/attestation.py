# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin attestation format and canonicalization.

A Pin is the attestation that travels alongside an embedding in vector
store metadata. It commits to:

  - the source text (by hash)
  - the model that produced the embedding (identifier + optional hash)
  - the embedding itself (by hash)
  - the producer (by signing key id)
  - the time of pinning

The wire form is a compact JSON object. The signature is over a
canonical byte sequence built by `PinHeader.canonicalize()` — NOT over
the JSON encoding — so that downstream re-serialization (whitespace,
key order) cannot invalidate signatures.

Protocol version: PROTOCOL_VERSION (currently 2). v2 includes a 14-byte
domain separator (`DOMAIN_TAG`) prepended to the canonical JSON before
signing, and binds BOTH `v` and `kid` into the signed payload to
prevent downgrade and key-swap attacks. See docs/spec.md §4.2 and §12
for the full rationale.

v2 is a wire-format break with v1; v1 pins do not verify under the
default v2 verifier. A `LegacyV1Verifier` is provided for migration.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

# ---- protocol identifiers ----

PROTOCOL_VERSION = 2

# 13 ASCII bytes: literally "vectorpin/v2" + NUL terminator. Prepended
# to canonical JSON before Ed25519 signing so a VectorPin v2 signature
# cannot collide with any other "signed canonical JSON" message.
#
# Note: docs/spec.md §2 and §4.2 describe this literal as "14 bytes"
# — that count is a typo in the spec; the literal `b"vectorpin/v2\x00"`
# is unambiguously 13 bytes (12 ASCII characters plus one NUL). The
# byte string IS the contract; cross-language ports MUST match these
# bytes regardless of the byte-count gloss in the spec text.
DOMAIN_TAG = b"vectorpin/v2\x00"
DOMAIN_TAG_LEN = 13
assert len(DOMAIN_TAG) == DOMAIN_TAG_LEN, (
    f"DOMAIN_TAG must be exactly {DOMAIN_TAG_LEN} bytes; got {len(DOMAIN_TAG)}"
)

# ---- parser limits (§4.3) ----

# Cap on the byte length of a JSON-encoded Pin we'll attempt to parse.
# Pin JSON in practice is well under a kilobyte; anything beyond this
# is either an attack or a corrupt record we don't want to allocate
# memory for.
MAX_PIN_JSON_BYTES = 65536

# `extra` field limits.
MAX_EXTRA_ENTRIES = 32
MAX_EXTRA_KEY_BYTES = 128
MAX_EXTRA_VALUE_BYTES = 1024

# Hard ceiling on vec_dim. 2^20 components is far above any real
# embedding while still preventing pathological allocations downstream.
MAX_VEC_DIM = 1_048_576

# Ed25519 raw signatures are exactly 64 bytes.
SIG_LEN = 64

# Strict format for sha256:<hex> hash strings used in source_hash,
# vec_hash, model_hash.
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Allowed vec_dtype values. Mirrors hash.CanonicalDtype but kept local
# to avoid an import cycle.
_ALLOWED_DTYPES = frozenset({"f32", "f64"})

# Strict v2 timestamp pattern: YYYY-MM-DDTHH:MM:SSZ, exactly. No
# fractional seconds, no offsets, no lowercase t/z.
_TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

# Top-level keys permitted in a v2 pin (§4.1). Anything else MUST be
# rejected at parse time to defeat field-injection attacks.
_ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {
        "v",
        "kid",
        "model",
        "model_hash",
        "source_hash",
        "vec_hash",
        "vec_dtype",
        "vec_dim",
        "ts",
        "extra",
        "sig",
    }
)


def _b64(data: bytes) -> str:
    """URL-safe base64, no padding — for compactness in wire form."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64dec(s: str) -> bytes:
    """Inverse of _b64; restores stripped padding."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _check_string_safe(value: str, field_name: str) -> None:
    """Reject control chars (U+0000-U+001F) and bidi overrides.

    Per §3.1, any string-typed field must be free of:
      - Control characters U+0000-U+001F
      - Bidirectional overrides U+202A-U+202E, U+2066-U+2069
    """
    for ch in value:
        cp = ord(ch)
        if cp < 0x20:
            raise ValueError(
                f"{field_name} contains control character U+{cp:04X}"
            )
        if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
            raise ValueError(
                f"{field_name} contains bidi-override character U+{cp:04X}"
            )


def _check_nfc(value: str, field_name: str) -> None:
    """Reject strings that are not already in Unicode NFC form."""
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{field_name} is not NFC-normalized")


@dataclass(frozen=True)
class PinHeader:
    """The signed portion of a Pin (everything except `sig`).

    Two Pins are equivalent iff their headers canonicalize to identical
    bytes. In v2, the header includes `v` and `kid` so both are bound
    by the signature.
    """

    v: int
    kid: str
    model: str
    source_hash: str
    vec_hash: str
    vec_dtype: str
    vec_dim: int
    ts: str
    model_hash: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Plain-dict view of the header, including `v` and `kid`.

        Used both for JSON serialization (via Pin.to_dict, which then
        adds `sig`) and for canonicalization (via canonicalize()).
        """
        out: dict[str, Any] = {
            "v": self.v,
            "kid": self.kid,
            "model": self.model,
            "source_hash": self.source_hash,
            "vec_hash": self.vec_hash,
            "vec_dtype": self.vec_dtype,
            "vec_dim": self.vec_dim,
            "ts": self.ts,
        }
        if self.model_hash is not None:
            out["model_hash"] = self.model_hash
        if self.extra:
            out["extra"] = dict(sorted(self.extra.items()))
        return out

    def canonicalize(self) -> bytes:
        """Stable byte representation for signing/verifying.

        Returns ``DOMAIN_TAG || canonical_json(header)`` where
        ``canonical_json`` is JSON with sorted keys, no whitespace,
        UTF-8 encoded, NFC-normalized strings, and `ensure_ascii=False`
        so non-ASCII NFC code points are emitted as raw UTF-8.

        All header fields — including `v` and `kid` — are included.
        The 14-byte domain tag prevents cross-protocol signature reuse.
        """
        # NFC every string field at canonicalization time so the bytes
        # match what a fresh-from-spec implementation would emit. We
        # also validate the well-formedness invariants the parser
        # enforces so signers can't silently emit a pin a verifier
        # would later reject.
        d = self.to_dict()
        # NFC-normalize the string-typed fields in place.
        d["kid"] = unicodedata.normalize("NFC", d["kid"])
        d["model"] = unicodedata.normalize("NFC", d["model"])
        d["ts"] = unicodedata.normalize("NFC", d["ts"])
        if "extra" in d:
            d["extra"] = {
                unicodedata.normalize("NFC", k): unicodedata.normalize("NFC", v)
                for k, v in d["extra"].items()
            }
            # Re-sort after NFC to keep canonical key order stable
            # under NFC composition (composed forms may differ in code
            # point ordering from decomposed forms).
            d["extra"] = dict(sorted(d["extra"].items()))

        body = json.dumps(
            d,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return DOMAIN_TAG + body


@dataclass(frozen=True)
class Pin:
    """An attestation binding an embedding to its source and producer.

    The `kid` and `v` fields live on the header (because they are
    signed) but the wire-format JSON still flattens them at the top
    level for compactness and readability.
    """

    header: PinHeader
    sig: bytes  # raw signature bytes (ed25519 = 64 bytes)

    @property
    def kid(self) -> str:
        """Convenience accessor — kid is part of the header."""
        return self.header.kid

    def to_dict(self) -> dict[str, Any]:
        d = self.header.to_dict()
        d["sig"] = _b64(self.sig)
        return d

    def to_json(self) -> str:
        """Compact JSON encoding suitable for vector DB metadata fields."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(
        cls, d: dict[str, Any], *, accept_versions: frozenset[int] | None = None
    ) -> Pin:
        """Parse a pin from a dict, enforcing all v2 wire-format rules.

        `accept_versions` is for internal use by the legacy verifier;
        callers should generally not pass it.
        """
        if not isinstance(d, dict):
            raise ValueError("pin must be a JSON object")

        # 1. Reject unknown top-level fields (§4.1).
        unknown = set(d.keys()) - _ALLOWED_TOP_LEVEL_KEYS
        if unknown:
            raise ValueError(
                f"pin contains unknown top-level field(s): {sorted(unknown)}"
            )

        # 2. Version check.
        v = d.get("v")
        allowed = accept_versions if accept_versions is not None else frozenset(
            {PROTOCOL_VERSION}
        )
        if v not in allowed:
            raise ValueError(
                f"unsupported pin version {v!r}; expected {sorted(allowed)}"
            )

        # 3. String field validation: type, NFC, control chars, bidi.
        model = d.get("model")
        if not isinstance(model, str) or not model:
            raise ValueError("model must be a non-empty string")
        _check_string_safe(model, "model")
        _check_nfc(model, "model")

        kid = d.get("kid")
        if not isinstance(kid, str) or not kid:
            raise ValueError("kid must be a non-empty string")
        _check_string_safe(kid, "kid")
        _check_nfc(kid, "kid")

        vec_dtype = d.get("vec_dtype")
        if vec_dtype not in _ALLOWED_DTYPES:
            raise ValueError(
                f"vec_dtype must be one of {sorted(_ALLOWED_DTYPES)}; got {vec_dtype!r}"
            )

        # 4. vec_dim: int (and not bool), in (0, MAX_VEC_DIM].
        vec_dim_raw = d.get("vec_dim")
        if not isinstance(vec_dim_raw, int) or isinstance(vec_dim_raw, bool):
            raise ValueError(
                f"vec_dim must be an int; got {type(vec_dim_raw).__name__}"
            )
        if not (0 < vec_dim_raw <= MAX_VEC_DIM):
            raise ValueError(
                f"vec_dim must be in (0, {MAX_VEC_DIM}]; got {vec_dim_raw}"
            )

        # 5. Hashes.
        source_hash = d.get("source_hash")
        if not isinstance(source_hash, str) or not _HASH_RE.match(source_hash):
            raise ValueError("source_hash must match 'sha256:<64 hex chars>'")

        vec_hash = d.get("vec_hash")
        if not isinstance(vec_hash, str) or not _HASH_RE.match(vec_hash):
            raise ValueError("vec_hash must match 'sha256:<64 hex chars>'")

        model_hash = d.get("model_hash")
        if model_hash is not None:
            if not isinstance(model_hash, str) or not _HASH_RE.match(model_hash):
                raise ValueError("model_hash must match 'sha256:<64 hex chars>'")

        # 6. Timestamp: strict regex; v1 mode allows any non-empty string.
        ts = d.get("ts")
        if not isinstance(ts, str) or not ts:
            raise ValueError("ts must be a non-empty string")
        if PROTOCOL_VERSION in allowed and v == PROTOCOL_VERSION:
            if not _TS_RE.match(ts):
                raise ValueError(
                    "ts must match 'YYYY-MM-DDTHH:MM:SSZ' exactly"
                )
            _check_string_safe(ts, "ts")
            _check_nfc(ts, "ts")

        # 7. extra: map<string, string>, bounded.
        extra_raw = d.get("extra", {})
        if not isinstance(extra_raw, dict):
            raise ValueError("extra must be an object")
        if len(extra_raw) > MAX_EXTRA_ENTRIES:
            raise ValueError(
                f"extra exceeds maximum {MAX_EXTRA_ENTRIES} entries"
            )
        extra: dict[str, str] = {}
        for k, val in extra_raw.items():
            if not isinstance(k, str):
                raise ValueError("extra keys must be strings")
            if not isinstance(val, str):
                raise ValueError("extra values must be strings")
            if len(k.encode("utf-8")) > MAX_EXTRA_KEY_BYTES:
                raise ValueError(
                    f"extra key exceeds maximum {MAX_EXTRA_KEY_BYTES} bytes"
                )
            if len(val.encode("utf-8")) > MAX_EXTRA_VALUE_BYTES:
                raise ValueError(
                    f"extra value exceeds maximum {MAX_EXTRA_VALUE_BYTES} bytes"
                )
            if v == PROTOCOL_VERSION:
                _check_string_safe(k, f"extra key {k!r}")
                _check_nfc(k, f"extra key {k!r}")
                _check_string_safe(val, f"extra[{k!r}]")
                _check_nfc(val, f"extra[{k!r}]")
            extra[k] = val

        # 8. Signature.
        sig_raw = d.get("sig")
        if not isinstance(sig_raw, str):
            raise ValueError("sig must be a base64-encoded string")
        try:
            sig_bytes = _b64dec(sig_raw)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"sig is not valid base64: {e}") from e
        if len(sig_bytes) != SIG_LEN:
            raise ValueError(
                f"sig must decode to exactly {SIG_LEN} bytes; got {len(sig_bytes)}"
            )

        header = PinHeader(
            v=int(v),
            kid=kid,
            model=model,
            source_hash=source_hash,
            vec_hash=vec_hash,
            vec_dtype=vec_dtype,
            vec_dim=int(vec_dim_raw),
            ts=ts,
            model_hash=model_hash,
            extra=extra,
        )
        return cls(header=header, sig=sig_bytes)

    @classmethod
    def from_json(
        cls, s: str, *, accept_versions: frozenset[int] | None = None
    ) -> Pin:
        # Measure the raw byte size before json.loads runs so we cap
        # parser memory use, not just the resulting object.
        s_bytes = s.encode("utf-8") if isinstance(s, str) else s
        if len(s_bytes) > MAX_PIN_JSON_BYTES:
            raise ValueError("pin JSON too large")
        return cls.from_dict(json.loads(s), accept_versions=accept_versions)


# ---- legacy v1 canonicalization (migration-only) ----


def _canonicalize_v1(header: PinHeader) -> bytes:
    """Reconstruct v1 canonical bytes for a header.

    v1 canonicalization differed from v2 in three ways:
      - No domain tag prefix.
      - `kid` was NOT included in the signed payload (it lived only at
        the Pin level, not the PinHeader level).
      - No strict NFC / control-char / bidi enforcement on string
        fields (these were silently passed through).

    The header dict emitted here matches v1.json's `canonical_header_b64`
    byte-for-byte so that pins generated by the v1 reference
    implementation continue to verify under LegacyV1Verifier.
    """
    out: dict[str, Any] = {
        "v": header.v,
        "model": header.model,
        "source_hash": header.source_hash,
        "vec_hash": header.vec_hash,
        "vec_dtype": header.vec_dtype,
        "vec_dim": header.vec_dim,
        "ts": header.ts,
    }
    if header.model_hash is not None:
        out["model_hash"] = header.model_hash
    if header.extra:
        out["extra"] = dict(sorted(header.extra.items()))
    return json.dumps(
        out, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
