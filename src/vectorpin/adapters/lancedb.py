# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""LanceDB adapter — the recommended default for VectorPin.

LanceDB is shipped first because it gives operators the deployment
ergonomics of an embedded library (no daemon, file-based dataset on
local fs or object storage) plus a typed columnar schema that holds
the Pin natively. There is no sidecar: the pin lives as a string
column on the table next to the vector, and Lance's versioned commit
protocol makes (vector, pin) writes atomic by construction.

This matches the choice made by the Symbiont runtime, which uses
LanceDB as its default embedded vector backend.

Install with: pip install 'vectorpin[lancedb]'
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import numpy as np

from vectorpin.adapters.base import PIN_METADATA_KEY, BaseAdapter, PinnedRecord
from vectorpin.attestation import Pin

# Default column names used by LanceDBAdapter. Override at construction
# time if your schema uses different names.
DEFAULT_ID_COLUMN = "id"
DEFAULT_VECTOR_COLUMN = "vector"

# Column names get inlined into SQL predicates without quoting, so the
# allow-list has to be airtight. Standard SQL identifier shape only.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_column_name(col: str, *, field: str = "id_column") -> str:
    """Reject column names that aren't safe to embed in a SQL predicate.

    LanceDB's `where` clauses are SQL expressions parsed by DataFusion,
    so a column name with whitespace, quotes, or punctuation could
    inject syntax. We only accept the standard identifier shape.
    """
    if not isinstance(col, str) or not _IDENT_RE.match(col):
        raise ValueError(f"invalid {field}: {col!r}")
    return col


def _validate_record_id(rid: str) -> str:
    """Reject record ids with control chars that the SQL escaper won't catch.

    Single-quote escaping handles SQL string literals, but a backslash
    or embedded NUL/newline can still confuse downstream consumers and
    log files. Refuse them at the boundary.
    """
    if not isinstance(rid, str):
        raise ValueError(f"record_id must be str; got {type(rid).__name__}")
    for ch in ("\x00", "\n", "\r", "\\"):
        if ch in rid:
            raise ValueError(f"record_id contains forbidden character {ch!r}")
    return rid


class LanceDBAdapter(BaseAdapter):
    """Wraps a LanceDB table for VectorPin reads and writes.

    The pin lives in a string column on the same row as the vector. We
    store JSON rather than binary so an operator inspecting the table
    with `tbl.head()` sees an attestation rather than opaque bytes.

    Concurrency model: Lance commits use optimistic concurrency
    control; concurrent calls to `attach_pin` against different ids
    are safe. Concurrent calls against the same id race on commit
    order — last writer wins, which matches the rest of the protocol.
    """

    def __init__(
        self,
        table: Any,
        *,
        id_column: str = DEFAULT_ID_COLUMN,
        vector_column: str = DEFAULT_VECTOR_COLUMN,
        pin_column: str = PIN_METADATA_KEY,
    ):
        self._table = table
        # Validate every column name we'll ever inline into a SQL
        # predicate. Cheaper to fail at construction than at query.
        self._id = _validate_column_name(id_column, field="id_column")
        self._vec = _validate_column_name(vector_column, field="vector_column")
        self._pin = _validate_column_name(pin_column, field="pin_column")

    @classmethod
    def connect(
        cls,
        uri: str,
        table_name: str,
        *,
        id_column: str = DEFAULT_ID_COLUMN,
        vector_column: str = DEFAULT_VECTOR_COLUMN,
        pin_column: str = PIN_METADATA_KEY,
    ) -> LanceDBAdapter:
        """Open an existing LanceDB table.

        `uri` accepts the same value as `lancedb.connect`: a local
        directory path, an `s3://` / `gs://` / `az://` URL, or a
        LanceDB Cloud connection string.
        """
        try:
            import lancedb
        except ImportError as e:
            raise ImportError(
                "lancedb not installed. Run: pip install 'vectorpin[lancedb]'"
            ) from e
        db = lancedb.connect(uri)
        table = db.open_table(table_name)
        return cls(
            table,
            id_column=id_column,
            vector_column=vector_column,
            pin_column=pin_column,
        )

    def iter_records(self, *, batch_size: int = 256) -> Iterator[PinnedRecord]:
        """Yield every record in the table.

        We pull the table as an Arrow table and iterate batches so the
        entire dataset is not held twice in Python at once. Lance
        scans return the original f32 vector regardless of any IVF/PQ
        index built on top of the table — pinning is meaningful
        against the input vector, which is what verification needs.
        """
        arrow_table = self._table.to_arrow()
        for batch in arrow_table.to_batches(max_chunksize=batch_size):
            yield from self._batch_to_records(batch)

    def get(self, record_id: str) -> PinnedRecord:
        rows = (
            self._table.search()
            .where(_id_predicate(self._id, record_id), prefilter=True)
            .limit(1)
            .to_arrow()
        )
        if rows.num_rows == 0:
            raise KeyError(record_id)
        return next(self._batch_to_records(rows.slice(0, 1)))

    def attach_pin(self, record_id: str, pin: Pin) -> None:
        # Lance's update API takes a SQL-style predicate and a values
        # dict; this is one round-trip and one new dataset version.
        self._table.update(
            where=_id_predicate(self._id, record_id),
            values={self._pin: pin.to_json()},
        )

    # ---- internals ----

    def _batch_to_records(self, batch: Any) -> Iterator[PinnedRecord]:
        """Convert one Arrow batch / table slice into PinnedRecords."""
        names = set(batch.schema.names)
        if self._id not in names:
            raise ValueError(
                f"table is missing required id column {self._id!r}; "
                f"present columns: {sorted(names)}"
            )
        if self._vec not in names:
            raise ValueError(
                f"table is missing required vector column {self._vec!r}; "
                f"present columns: {sorted(names)}"
            )
        ids = batch.column(self._id).to_pylist()
        vectors = batch.column(self._vec).to_pylist()
        pin_strs = (
            batch.column(self._pin).to_pylist() if self._pin in names else [None] * batch.num_rows
        )
        # Build a metadata dict from anything that isn't the id/vec/pin.
        reserved = {self._id, self._vec, self._pin}
        passthrough_cols = [c for c in batch.schema.names if c not in reserved]
        passthrough = {c: batch.column(c).to_pylist() for c in passthrough_cols}

        for i, rid in enumerate(ids):
            vector = np.asarray(vectors[i], dtype=np.float32)
            if vector.ndim != 1:
                raise ValueError(
                    f"vector column {self._vec!r} returned non-1D shape {vector.shape}"
                )
            pin_str = pin_strs[i]
            pin = Pin.from_json(pin_str) if pin_str else None
            metadata = {c: passthrough[c][i] for c in passthrough_cols}
            yield PinnedRecord(
                id=str(rid),
                vector=vector,
                pin=pin,
                metadata=metadata,
            )


def _id_predicate(column: str, record_id: str) -> str:
    """Build a SQL predicate matching one record id.

    Lance's where-clause is a SQL expression evaluated by DataFusion.
    We escape single quotes by doubling them, which is the canonical
    SQL string-literal escape and what DataFusion expects. The column
    name and id are also validated up front against control chars and
    non-identifier shapes so this string interpolation is safe.
    """
    _validate_column_name(column, field="id_column")
    _validate_record_id(record_id)
    escaped = record_id.replace("'", "''")
    return f"{column} = '{escaped}'"
