# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Canonical hashing for embeddings, source content, and metadata.

The protocol is built on three reproducible operations:

  1. canonical_vector_bytes(vector, dtype) -> bytes
     Produces a byte sequence that two implementations will agree on for
     the same float32/float64 array.

  2. hash_vector(vector, dtype) -> "sha256:<hex>"
     SHA-256 over the canonical bytes.

  3. hash_text(text) -> "sha256:<hex>"
     SHA-256 over UTF-8 NFC-normalized text bytes.

These are the only places where bytes get mixed with semantics. Every
attestation field is one of: an explicit string, a hash, a timestamp, or
a signature. No implicit serialization.
"""

from __future__ import annotations

import hashlib
import os
import unicodedata
from collections.abc import Iterable
from pathlib import Path

import numpy as np

# ---- vector hashing ----

CanonicalDtype = str  # "f32" | "f64"

# Byte width of each canonical dtype. Used by the verifier's precision
# check (§3.2): a supplied vector whose native element width is larger
# than the pinned dtype's width carries bits the hash never sees.
_DTYPE_ITEMSIZE: dict[str, int] = {"f32": 4, "f64": 8}


def _np_dtype(dtype: CanonicalDtype) -> np.dtype:
    if dtype == "f32":
        return np.dtype("<f4")  # little-endian float32
    if dtype == "f64":
        return np.dtype("<f8")  # little-endian float64
    raise ValueError(f"unsupported canonical dtype: {dtype!r}")


def dtype_itemsize(dtype: CanonicalDtype) -> int:
    """Byte width of one element under a canonical dtype (4 or 8)."""
    try:
        return _DTYPE_ITEMSIZE[dtype]
    except KeyError:
        raise ValueError(f"unsupported canonical dtype: {dtype!r}") from None


def native_dtype(vector: np.ndarray) -> CanonicalDtype:
    """Return the canonical dtype that losslessly represents ``vector``.

    ``float32`` (and narrower floats such as ``float16``, which widen
    exactly) map to ``"f32"``; ``float64`` maps to ``"f64"``. Non-float
    arrays and wider-than-64-bit floats raise so a caller never commits
    to a dtype that silently rounds its data: pass ``vec_dtype``
    explicitly in that case.
    """
    dt = np.dtype(vector.dtype)
    if dt.kind != "f":
        raise ValueError(
            f"cannot infer canonical dtype for non-float array dtype {dt}; "
            "pass vec_dtype explicitly"
        )
    if dt.itemsize <= 4:
        return "f32"
    if dt.itemsize == 8:
        return "f64"
    raise ValueError(
        f"cannot infer canonical dtype for {dt} (wider than 64 bits); "
        "pass vec_dtype explicitly"
    )


def is_wider_than(vector: np.ndarray, dtype: CanonicalDtype) -> bool:
    """True iff ``vector`` holds more precision than ``dtype`` can carry.

    A verifier that casts such a vector before hashing would accept any
    modification confined to the discarded low-order bits, so §3.2
    requires rejecting it. Non-float arrays are treated as wider: their
    cast to a float dtype is lossy for large magnitudes and there is no
    honest reason for a store to hand a verifier integer data.
    """
    dt = np.dtype(vector.dtype)
    if dt.kind != "f":
        return True
    return dt.itemsize > dtype_itemsize(dtype)


def canonical_vector_bytes(vector: np.ndarray, dtype: CanonicalDtype = "f32") -> bytes:
    """Return reproducible bytes for an embedding vector.

    Always little-endian, always 1-D. The dtype is fixed by the caller so
    two implementations reach the same byte sequence regardless of how the
    array was constructed.

    This helper casts; it does not police precision. The verifier is
    responsible for refusing a vector wider than the pinned dtype (see
    :func:`is_wider_than`) before it ever reaches this function.
    """
    if vector.ndim != 1:
        raise ValueError(f"expected 1-D vector, got shape {vector.shape}")
    target = _np_dtype(dtype)
    arr = np.ascontiguousarray(vector.astype(target, copy=False))
    return arr.tobytes()


def hash_vector(vector: np.ndarray, dtype: CanonicalDtype = "f32") -> str:
    """Return the canonical hash of an embedding vector as 'sha256:<hex>'."""
    digest = hashlib.sha256(canonical_vector_bytes(vector, dtype)).hexdigest()
    return f"sha256:{digest}"


# ---- text hashing ----


def hash_text(text: str) -> str:
    """Return the canonical hash of a source text chunk as 'sha256:<hex>'.

    Text is normalized to Unicode NFC then encoded as UTF-8 before hashing.
    NFC chosen because it is the form the W3C and most embedding model
    tokenizers expect; this prevents trivial false-mismatches from upstream
    normalization differences.

    Raises ``ValueError`` if the text contains a lone surrogate code
    point: such a string has no UTF-8 encoding, so it has no canonical
    hash either (the Rust and TypeScript ports reject it the same way).
    """
    nfc = unicodedata.normalize("NFC", text)
    try:
        encoded = nfc.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValueError("text contains a lone surrogate code point") from e
    digest = hashlib.sha256(encoded).hexdigest()
    return f"sha256:{digest}"


def hash_files(paths: Iterable[str | os.PathLike[str]]) -> str:
    """SHA-256 over the concatenated contents of ``paths``, as 'sha256:<hex>'.

    This is the ``model_hash`` convention from spec §4.1: the input is
    the byte-concatenation of every model weight shard, ordered by the
    shard's base filename (ASCII sort, not locale sort). Files are
    streamed so multi-gigabyte checkpoints do not have to fit in memory.
    """
    ordered = sorted((Path(p) for p in paths), key=lambda p: p.name)
    h = hashlib.sha256()
    for path in ordered:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def hash_bytes(data: bytes) -> str:
    """SHA-256 over raw bytes, returned as 'sha256:<hex>'."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"
