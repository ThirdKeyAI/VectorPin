# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""LanceDBAdapter roundtrip tests.

Skipped automatically when `lancedb` is not installed. The adapter is
exercised against a temp-dir-backed Lance dataset; no daemon or
network access is required.
"""

from __future__ import annotations

import numpy as np
import pytest

lancedb = pytest.importorskip("lancedb")
pa = pytest.importorskip("pyarrow")

from vectorpin import Signer, Verifier
from vectorpin.adapters import PIN_METADATA_KEY, LanceDBAdapter


@pytest.fixture
def lance_table(tmp_path):
    """Create a small Lance table with two rows; no pins attached yet."""
    db = lancedb.connect(str(tmp_path / "lance_db"))
    rows = [
        {"id": "a", "vector": [0.1] * 16, "source": "alpha"},
        {"id": "b", "vector": [0.2] * 16, "source": "beta"},
    ]
    schema = pa.schema(
        [
            ("id", pa.string()),
            ("vector", pa.list_(pa.float32(), 16)),
            ("source", pa.string()),
            (PIN_METADATA_KEY, pa.string()),
        ]
    )
    # Lance expects the column to exist if we want to update it later;
    # creating with the schema lets us start with NULL pin values.
    initial = [{**r, PIN_METADATA_KEY: None} for r in rows]
    return db.create_table("test", data=initial, schema=schema)


def test_iter_records_returns_unpinned(lance_table):
    adapter = LanceDBAdapter(lance_table)
    records = list(adapter.iter_records())
    assert len(records) == 2
    assert {r.id for r in records} == {"a", "b"}
    assert all(r.pin is None for r in records)
    for r in records:
        assert r.vector.shape == (16,)
        assert r.metadata.get("source") in {"alpha", "beta"}


def test_attach_pin_and_get(lance_table):
    adapter = LanceDBAdapter(lance_table)
    signer = Signer.generate(key_id="test-key")

    rec = adapter.get("a")
    assert rec.pin is None

    pin = signer.pin(source="alpha", model="bench-model", vector=rec.vector)
    adapter.attach_pin("a", pin)

    refreshed = adapter.get("a")
    assert refreshed.pin is not None
    assert refreshed.pin.kid == "test-key"
    assert refreshed.pin.header.model == "bench-model"


def test_full_roundtrip_verifies(lance_table):
    adapter = LanceDBAdapter(lance_table)
    signer = Signer.generate(key_id="test-key")
    verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})

    for record in adapter.iter_records():
        pin = signer.pin(
            source=str(record.metadata["source"]),
            model="bench-model",
            vector=record.vector,
        )
        adapter.attach_pin(record.id, pin)

    for record in adapter.iter_records():
        assert record.pin is not None
        result = verifier.verify(
            record.pin,
            source=str(record.metadata["source"]),
            vector=record.vector,
        )
        assert result, f"verify failed for {record.id}: {result.error}"


def test_get_missing_id_raises(lance_table):
    adapter = LanceDBAdapter(lance_table)
    with pytest.raises(KeyError):
        adapter.get("nonexistent-id")


def test_constructor_rejects_invalid_id_column(lance_table):
    """Column names that aren't valid SQL identifiers must be refused."""
    for bad in ("id; DROP TABLE x", "id'", "1id", "id-x", "id with space", ""):
        with pytest.raises(ValueError, match="id_column"):
            LanceDBAdapter(lance_table, id_column=bad)


def test_constructor_rejects_invalid_vector_column(lance_table):
    with pytest.raises(ValueError, match="vector_column"):
        LanceDBAdapter(lance_table, vector_column="vec; DROP TABLE x")


def test_id_predicate_rejects_record_id_with_null_byte(lance_table):
    """Record ids with control chars or backslashes must be refused."""
    adapter = LanceDBAdapter(lance_table)
    with pytest.raises(ValueError, match="forbidden character"):
        adapter.get("foo\x00bar")


def test_id_predicate_rejects_record_id_with_newline(lance_table):
    adapter = LanceDBAdapter(lance_table)
    with pytest.raises(ValueError, match="forbidden character"):
        adapter.get("foo\nbar")


def test_id_predicate_rejects_record_id_with_backslash(lance_table):
    adapter = LanceDBAdapter(lance_table)
    with pytest.raises(ValueError, match="forbidden character"):
        adapter.get("foo\\bar")


def test_id_predicate_allows_quote_in_record_id(lance_table):
    """Single quotes are still safely escaped via doubling — not rejected."""
    adapter = LanceDBAdapter(lance_table)
    # No such record, but the predicate must build without raising.
    with pytest.raises(KeyError):
        adapter.get("o'brien")


def test_tampered_vector_caught_after_pin(lance_table):
    """Sanity check: pinning a vector then mutating the array invalidates verify."""
    adapter = LanceDBAdapter(lance_table)
    signer = Signer.generate(key_id="test-key")
    verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})

    rec = adapter.get("a")
    pin = signer.pin(source="alpha", model="bench-model", vector=rec.vector)
    adapter.attach_pin("a", pin)

    refreshed = adapter.get("a")
    tampered = refreshed.vector.copy()
    tampered[0] = float(np.float32(tampered[0]) + np.float32(1e-3))
    result = verifier.verify(refreshed.pin, source="alpha", vector=tampered)
    assert not result
    assert result.error.value == "vector_tampered"
