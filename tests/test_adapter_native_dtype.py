# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""VP-1 at the adapter boundary: adapters return the store's native precision.

Every shipped adapter used to coerce vectors to float32 before the
verifier saw them, which made the audit CLI structurally unable to
notice bits hidden below float32 precision in a float64-backed store.
"""

from __future__ import annotations

import numpy as np
import pytest

from vectorpin import Signer, Verifier, VerifyError
from vectorpin.adapters.base import vector_from_store


def _hide_payload_in_low_bits(v64: np.ndarray, seed: int = 2) -> np.ndarray:
    rng = np.random.default_rng(seed)
    bits = v64.view(np.uint64).copy()
    payload = rng.integers(1, 1 << 28, size=v64.shape[0], dtype=np.uint64)
    mask = np.uint64((1 << 28) - 1)
    bits = (bits & ~mask) | payload
    modified = bits.view(np.float64)
    assert np.array_equal(modified.astype(np.float32), v64.astype(np.float32))
    assert not np.array_equal(modified, v64)
    return modified


# ---- adapters return native precision ---------------------------------------


def test_lancedb_adapter_returns_float64_for_float64_column(tmp_path) -> None:
    lancedb = pytest.importorskip("lancedb")
    pa = pytest.importorskip("pyarrow")
    from vectorpin.adapters import PIN_METADATA_KEY, LanceDBAdapter

    db = lancedb.connect(str(tmp_path / "db"))
    schema = pa.schema(
        [
            ("id", pa.string()),
            ("vector", pa.list_(pa.float64(), 4)),
            (PIN_METADATA_KEY, pa.string()),
        ]
    )
    v64 = np.array([0.1, 0.2, 0.3, 0.4], dtype=np.float64)
    tbl = db.create_table(
        "t", data=[{"id": "a", "vector": v64.tolist(), PIN_METADATA_KEY: None}], schema=schema
    )
    adapter = LanceDBAdapter(tbl)
    rec = adapter.get("a")
    assert rec.vector.dtype == np.float64
    assert np.array_equal(rec.vector, v64)

    # The end-to-end channel: pin as f32 (the old default), store f64,
    # rewrite the low bits. The audit path must reject, not accept.
    signer = Signer.generate(key_id="k")
    verifier = Verifier({"k": signer.public_key_bytes()})
    pin = signer.pin(source="s", model="m", vector=v64, vec_dtype="f32")
    adapter.attach_pin("a", pin)
    modified = _hide_payload_in_low_bits(v64)
    tbl.update(where="id = 'a'", values={"vector": modified.tolist()})
    rec = adapter.get("a")
    assert rec.vector.dtype == np.float64
    assert not np.array_equal(rec.vector, v64)
    result = verifier.verify(rec.pin, vector=rec.vector)
    assert result.error is VerifyError.SHAPE_MISMATCH
    # And pinning under the native f64 dtype catches the same rewrite.
    pin64 = signer.pin(source="s", model="m", vector=v64)
    assert verifier.verify(pin64, vector=rec.vector).error is VerifyError.VECTOR_TAMPERED


def test_lancedb_adapter_returns_float32_for_float32_column(tmp_path) -> None:
    lancedb = pytest.importorskip("lancedb")
    pa = pytest.importorskip("pyarrow")
    from vectorpin.adapters import LanceDBAdapter

    db = lancedb.connect(str(tmp_path / "db"))
    schema = pa.schema([("id", pa.string()), ("vector", pa.list_(pa.float32(), 4))])
    tbl = db.create_table("t", data=[{"id": "a", "vector": [0.1] * 4}], schema=schema)
    assert LanceDBAdapter(tbl).get("a").vector.dtype == np.float32


def test_chroma_adapter_keeps_store_precision(tmp_path) -> None:
    chromadb = pytest.importorskip("chromadb")
    from vectorpin.adapters import ChromaAdapter

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    coll = client.create_collection(name="native-dtype")
    coll.add(ids=["a"], embeddings=[[0.1, 0.2, 0.3]])
    rec = ChromaAdapter(coll).get("a")
    # Chroma persists float32; whatever the client hands back, the
    # verifier-facing array must be the single-precision values.
    assert rec.vector.dtype == np.float32
def test_vector_from_store_narrowing_must_be_exact() -> None:
    """A backend that returns values wider than its declared precision is
    an error, never a silent cast."""

    exact = np.array([0.1, 0.2], dtype=np.float32).astype(np.float64)
    assert vector_from_store(exact, native_dtype=np.float32).dtype == np.float32
    assert vector_from_store(exact.tolist(), native_dtype=np.float32).dtype == np.float32
    inexact = np.array([0.1, 0.2], dtype=np.float64)
    with pytest.raises(ValueError, match="more precision"):
        vector_from_store(inexact, native_dtype=np.float32)
    # No declared dtype: ndarrays keep theirs, sequences are float64.
    assert vector_from_store(inexact).dtype == np.float64
    assert vector_from_store([0.1, 0.2]).dtype == np.float64
    assert vector_from_store(np.zeros(2, dtype=np.float16)).dtype == np.float16
