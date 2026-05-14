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
canonical byte sequence built by `canonicalize()`, NOT over the JSON
encoding — this is so that downstream re-serialization (whitespace,
key order) cannot invalidate signatures.

Protocol version: PROTOCOL_VERSION (currently 1). Older readers MUST
reject unknown versions.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = 1

# Cap on the byte length of a JSON-encoded Pin we'll attempt to parse.
# Pin JSON in practice is well under a kilobyte; anything beyond this is
# either an attack or a corrupt record we don't want to allocate memory
# for.
MAX_PIN_JSON_BYTES = 65536

# Strict format for sha256:<hex> hash strings used in source_hash,
# vec_hash, model_hash.
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Allowed vec_dtype values. Mirrors hash.CanonicalDtype but kept local
# to avoid an import cycle.
_ALLOWED_DTYPES = frozenset({"f32", "f64"})

# Hard ceiling on vec_dim. 1M components is far above any real embedding
# while still preventing pathological allocations downstream.
_MAX_VEC_DIM = 1_048_576

# Ed25519 raw signatures are exactly 64 bytes.
_SIG_LEN = 64


def _b64(data: bytes) -> str:
    """URL-safe base64, no padding — for compactness in wire form."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64dec(s: str) -> bytes:
    """Inverse of _b64; restores stripped padding."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


@dataclass(frozen=True)
class PinHeader:
    """The signed portion of a Pin.

    Everything except `sig` and `kid` lives here. Two Pins are
    equivalent iff their headers canonicalize to identical bytes.
    """

    v: int
    model: str
    source_hash: str
    vec_hash: str
    vec_dtype: str
    vec_dim: int
    ts: str
    model_hash: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "v": self.v,
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

        Uses JSON with sorted keys, no whitespace. This is the form of
        canonicalization that has the best library support across
        languages while still being deterministic.
        """
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")


@dataclass(frozen=True)
class Pin:
    """An attestation binding an embedding to its source and producer."""

    header: PinHeader
    kid: str
    sig: bytes  # raw signature bytes (ed25519 = 64 bytes)

    def to_dict(self) -> dict[str, Any]:
        d = self.header.to_dict()
        d["kid"] = self.kid
        d["sig"] = _b64(self.sig)
        return d

    def to_json(self) -> str:
        """Compact JSON encoding suitable for vector DB metadata fields."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Pin:
        if not isinstance(d, dict):
            raise ValueError("pin must be a JSON object")

        v = d.get("v")
        if v != PROTOCOL_VERSION:
            raise ValueError(f"unsupported pin version {v!r}; expected {PROTOCOL_VERSION}")

        model = d.get("model")
        if not isinstance(model, str) or not model:
            raise ValueError("model must be a non-empty string")

        kid = d.get("kid")
        if not isinstance(kid, str) or not kid:
            raise ValueError("kid must be a non-empty string")

        vec_dtype = d.get("vec_dtype")
        if vec_dtype not in _ALLOWED_DTYPES:
            raise ValueError(
                f"vec_dtype must be one of {sorted(_ALLOWED_DTYPES)}; got {vec_dtype!r}"
            )

        vec_dim_raw = d.get("vec_dim")
        # bool is a subclass of int; explicitly reject it.
        if not isinstance(vec_dim_raw, int) or isinstance(vec_dim_raw, bool):
            raise ValueError(f"vec_dim must be an int; got {type(vec_dim_raw).__name__}")
        if not (0 < vec_dim_raw <= _MAX_VEC_DIM):
            raise ValueError(
                f"vec_dim must be in (0, {_MAX_VEC_DIM}]; got {vec_dim_raw}"
            )

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

        ts = d.get("ts")
        if not isinstance(ts, str) or not ts:
            raise ValueError("ts must be a non-empty string")

        extra_raw = d.get("extra", {})
        if not isinstance(extra_raw, dict):
            raise ValueError("extra must be an object")
        extra: dict[str, str] = {}
        for k, val in extra_raw.items():
            if not isinstance(k, str):
                raise ValueError("extra keys must be strings")
            if not isinstance(val, str):
                raise ValueError("extra values must be strings")
            extra[k] = val

        sig_raw = d.get("sig")
        if not isinstance(sig_raw, str):
            raise ValueError("sig must be a base64-encoded string")
        try:
            sig_bytes = _b64dec(sig_raw)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"sig is not valid base64: {e}") from e
        if len(sig_bytes) != _SIG_LEN:
            raise ValueError(
                f"sig must decode to exactly {_SIG_LEN} bytes; got {len(sig_bytes)}"
            )

        header = PinHeader(
            v=v,
            model=model,
            source_hash=source_hash,
            vec_hash=vec_hash,
            vec_dtype=vec_dtype,
            vec_dim=int(vec_dim_raw),
            ts=ts,
            model_hash=model_hash,
            extra=extra,
        )
        return cls(header=header, kid=kid, sig=sig_bytes)

    @classmethod
    def from_json(cls, s: str) -> Pin:
        # Measure the raw byte size *before* json.loads runs so we cap
        # parser memory use, not just the resulting object.
        s_bytes = s.encode("utf-8") if isinstance(s, str) else s
        if len(s_bytes) > MAX_PIN_JSON_BYTES:
            raise ValueError("pin JSON too large")
        return cls.from_dict(json.loads(s))
