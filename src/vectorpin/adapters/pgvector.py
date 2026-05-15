# Copyright 2025-2026 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""pgvector adapter.

pgvector is the de-facto vector store for teams that already operate
PostgreSQL and want to bolt embedding search onto an existing OLTP
database rather than stand up a dedicated vector service. From a
provenance perspective this is the most adversarial deployment shape:
a vector row is structurally indistinguishable from any other row, so
RBAC, backup, replication, and CDC pipelines all treat a poisoned
embedding as ordinary data. VectorPin's role in this environment is to
make the integrity property explicit — a verifier (the audit loop) can
walk the table out-of-band and surface any vector that doesn't match
its signed source/model binding.

The on-disk shape this adapter expects is a single table with at least:

  - an identifier column (default: ``id``, TEXT-typed),
  - a ``pgvector.vector`` column (default: ``embedding``),
  - a JSONB pin column (default: ``vectorpin``).

The pin column holds the canonical Pin JSON string (matching what
:meth:`vectorpin.attestation.Pin.to_json` emits) or NULL. Storing the
pin as JSONB rather than TEXT means downstream operators can index or
query into pin fields (``WHERE vectorpin->>'kid' = 'prod-2026-05'``)
without changing the adapter contract.

Install with: ``pip install 'vectorpin[pgvector]'``
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import numpy as np

from vectorpin.adapters.base import PIN_METADATA_KEY, BaseAdapter, PinnedRecord
from vectorpin.attestation import Pin

if TYPE_CHECKING:
    import psycopg

_DEFAULT_TABLE = "embeddings"
_DEFAULT_ID_COLUMN = "id"
_DEFAULT_VECTOR_COLUMN = "embedding"
_DEFAULT_PIN_COLUMN = PIN_METADATA_KEY

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _validate_identifier(name: str, *, field: str) -> str:
    """Reject anything that doesn't look like a bare SQL identifier.

    pgvector / postgres has no parameterized form for table or column
    names, so adapters that interpolate them MUST validate against a
    strict allowlist. Matches the LanceDB adapter's contract.
    """
    if not _IDENT_RE.match(name):
        raise ValueError(
            f"invalid {field}: {name!r} (must match {_IDENT_RE.pattern})"
        )
    return name


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    h = host.strip("[]").lower()
    if h in _LOOPBACK_HOSTS:
        return True
    return h.startswith("127.")


def _enforce_tls(dsn: str) -> None:
    """Refuse plaintext postgres connections to non-loopback hosts.

    Postgres credentials (``user:password@host``) typically live inside
    the DSN string itself, so the same threat model as the Qdrant
    adapter applies: a plaintext connection to a remote host leaks the
    credential. Postgres TLS is controlled via the ``sslmode`` query
    parameter; this check considers ``sslmode in {require, verify-ca,
    verify-full}`` as TLS-enabled. ``sslmode`` absent or set to
    ``disable``/``allow``/``prefer`` is treated as plaintext.

    Set ``VECTORPIN_ALLOW_INSECURE_HTTP=1`` (env-scoped escape hatch,
    same as the Qdrant adapter) to bypass for trusted in-cluster overlay
    deployments.
    """
    parsed = urlparse(dsn)
    if parsed.scheme not in {"postgresql", "postgres"}:
        # Non-URL DSNs (e.g. keyword=value form) — leave the decision
        # to libpq; nothing we can safely parse here.
        return
    if _is_loopback(parsed.hostname):
        return
    # Look for sslmode in the query string.
    query = parsed.query or ""
    sslmode = None
    for pair in query.split("&"):
        if pair.startswith("sslmode="):
            sslmode = pair.split("=", 1)[1].lower()
    if sslmode in {"require", "verify-ca", "verify-full"}:
        return
    if os.environ.get("VECTORPIN_ALLOW_INSECURE_HTTP") == "1":
        return
    raise ValueError(
        "pgvector DSN to a non-loopback host without sslmode=require "
        "refused (set VECTORPIN_ALLOW_INSECURE_HTTP=1 if you know what "
        "you're doing, or append ?sslmode=require to the DSN)"
    )


class PgVectorAdapter(BaseAdapter):
    """Wraps a pgvector-equipped Postgres table for VectorPin reads and writes.

    The adapter does not create the table — it only reads and updates.
    Operators are expected to have provisioned the table with their own
    schema; the only constraints VectorPin imposes are (a) the pin
    column is JSONB or TEXT, (b) the vector column is a pgvector
    ``vector(N)``, (c) the id column is comparable with ``=`` against a
    Python string.
    """

    def __init__(
        self,
        conn: psycopg.Connection,
        table_name: str,
        *,
        id_column: str = _DEFAULT_ID_COLUMN,
        vector_column: str = _DEFAULT_VECTOR_COLUMN,
        pin_column: str = _DEFAULT_PIN_COLUMN,
    ) -> None:
        self._conn = conn
        self._table = _validate_identifier(table_name, field="table_name")
        self._id = _validate_identifier(id_column, field="id_column")
        self._vec = _validate_identifier(vector_column, field="vector_column")
        self._pin = _validate_identifier(pin_column, field="pin_column")
        # Register the pgvector type adapter on the connection if it
        # isn't already registered. Safe to call repeatedly.
        try:
            from pgvector.psycopg import register_vector
            register_vector(self._conn)
        except ImportError as e:
            raise ImportError(
                "pgvector not installed. Run: pip install 'vectorpin[pgvector]'"
            ) from e

    @classmethod
    def connect(
        cls,
        dsn: str,
        table_name: str,
        *,
        id_column: str = _DEFAULT_ID_COLUMN,
        vector_column: str = _DEFAULT_VECTOR_COLUMN,
        pin_column: str = _DEFAULT_PIN_COLUMN,
    ) -> PgVectorAdapter:
        """Open a Postgres connection and wrap a pgvector table.

        The DSN must use ``sslmode=require`` (or stronger) for any
        non-loopback host. See :func:`_enforce_tls`.
        """
        _enforce_tls(dsn)
        try:
            import psycopg
        except ImportError as e:
            raise ImportError(
                "psycopg not installed. Run: pip install 'vectorpin[pgvector]'"
            ) from e
        conn = psycopg.connect(dsn, autocommit=True)
        return cls(
            conn,
            table_name,
            id_column=id_column,
            vector_column=vector_column,
            pin_column=pin_column,
        )

    def iter_records(self, *, batch_size: int = 256) -> Iterator[PinnedRecord]:
        # Client-side cursor + fetchmany bounds the working set without
        # requiring an explicit transaction. (Postgres server-side named
        # cursors need a transaction; in autocommit mode psycopg refuses
        # to DECLARE CURSOR — we'd have to drop autocommit just for the
        # walk, which is more state to manage than fetchmany.)
        sql = (
            f'SELECT "{self._id}", "{self._vec}", "{self._pin}" '
            f'FROM "{self._table}" '
            f'ORDER BY "{self._id}"'
        )
        chunk = max(1, batch_size)
        with self._conn.cursor() as cur:
            cur.execute(sql)
            while True:
                rows = cur.fetchmany(chunk)
                if not rows:
                    return
                for row in rows:
                    yield self._row_to_record(row)

    def get(self, record_id: str) -> PinnedRecord:
        sql = (
            f'SELECT "{self._id}", "{self._vec}", "{self._pin}" '
            f'FROM "{self._table}" WHERE "{self._id}" = %s'
        )
        with self._conn.cursor() as cur:
            cur.execute(sql, (record_id,))
            row = cur.fetchone()
        if row is None:
            raise KeyError(record_id)
        return self._row_to_record(row)

    def attach_pin(self, record_id: str, pin: Pin) -> None:
        # Store the pin as JSON. psycopg can cast a Python dict directly
        # to JSONB via ``Jsonb``, but going through a plain ``::jsonb``
        # cast on the placeholder keeps the adapter agnostic about
        # whether the pin column is JSONB or TEXT.
        sql = (
            f'UPDATE "{self._table}" SET "{self._pin}" = %s::jsonb '
            f'WHERE "{self._id}" = %s'
        )
        with self._conn.cursor() as cur:
            cur.execute(sql, (pin.to_json(), record_id))
            if cur.rowcount == 0:
                raise KeyError(record_id)

    # ---- internals ----

    def _row_to_record(self, row: tuple[Any, Any, Any]) -> PinnedRecord:
        rid, embedding, pin_payload = row
        if embedding is None:
            raise ValueError(
                f"record {rid!r} has no vector in column {self._vec!r}"
            )
        vector = np.asarray(embedding, dtype=np.float32)
        if vector.ndim != 1:
            raise ValueError(
                f"vector for {rid!r} returned non-1D shape {vector.shape}"
            )
        pin: Pin | None = None
        if pin_payload is not None:
            # JSONB columns come back as already-decoded Python objects
            # (dict). TEXT columns come back as str. Handle both.
            if isinstance(pin_payload, str):
                pin = Pin.from_json(pin_payload)
            elif isinstance(pin_payload, dict):
                pin = Pin.from_dict(pin_payload)
            else:
                # Unknown shape — surface as JSON for the strict parser.
                pin = Pin.from_json(json.dumps(pin_payload))
        return PinnedRecord(
            id=str(rid),
            vector=vector,
            pin=pin,
            metadata={},
        )
