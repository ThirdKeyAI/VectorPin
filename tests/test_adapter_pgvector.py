# Copyright 2025-2026 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""PgVectorAdapter roundtrip tests.

Two layers run here:

1. Offline unit tests (run whenever ``psycopg`` is importable) — they
   exercise the TLS guard, identifier validation, and constructor
   plumbing without touching a database. These guard the security-
   sensitive surface the audit found (parser/SQL-injection / leaked-
   credential / mistyped identifier paths).

2. Integration tests (run when ``PGVECTOR_URL`` points at a reachable
   pgvector-equipped Postgres) — they walk a real table end-to-end:
   create a schema, write two rows, attach pins, audit, verify under
   :class:`Verifier`. Skipped silently otherwise. The VectorSmuggle
   compose file in ``test_vector_dbs_docker/`` exposes a suitable
   instance: ``postgresql://postgres:mypassword@localhost:5432/vectordb``.
"""

from __future__ import annotations

import os
import uuid

import numpy as np
import pytest

psycopg = pytest.importorskip("psycopg")
pgvector = pytest.importorskip("pgvector")
from pgvector.psycopg import register_vector

from vectorpin import Signer, Verifier
from vectorpin.adapters import PIN_METADATA_KEY, PgVectorAdapter
from vectorpin.adapters.pgvector import (
    _enforce_tls,
    _validate_identifier,
)

# ---- offline tests (no database needed) ------------------------------------


def test_validate_identifier_accepts_normal_names():
    assert _validate_identifier("embeddings", field="x") == "embeddings"
    assert _validate_identifier("Embedding_Column_2", field="x") == "Embedding_Column_2"
    assert _validate_identifier("_underscored", field="x") == "_underscored"


@pytest.mark.parametrize(
    "bad",
    [
        "1starts_with_digit",
        "has space",
        'has"quote',
        "has;semicolon",
        "drop table foo --",
        "",
        "newline\nin\nname",
        "tab\tname",
    ],
)
def test_validate_identifier_rejects_hostile_names(bad):
    with pytest.raises(ValueError, match="invalid"):
        _validate_identifier(bad, field="x")


def test_enforce_tls_allows_loopback_plaintext():
    # Loopback hosts are exempt from the TLS requirement.
    _enforce_tls("postgresql://u:p@localhost:5432/db")
    _enforce_tls("postgresql://u:p@127.0.0.1:5432/db")
    _enforce_tls("postgresql://u:p@[::1]:5432/db")
    _enforce_tls("postgresql://u:p@127.0.0.42:5432/db")


def test_enforce_tls_allows_sslmode_require():
    _enforce_tls("postgresql://u:p@db.example.com:5432/x?sslmode=require")
    _enforce_tls("postgresql://u:p@db.example.com:5432/x?sslmode=verify-ca")
    _enforce_tls("postgresql://u:p@db.example.com:5432/x?sslmode=verify-full")


def test_enforce_tls_rejects_remote_plaintext():
    with pytest.raises(ValueError, match="sslmode=require"):
        _enforce_tls("postgresql://u:p@db.example.com:5432/x")
    with pytest.raises(ValueError, match="sslmode=require"):
        _enforce_tls("postgresql://u:p@db.example.com:5432/x?sslmode=prefer")
    with pytest.raises(ValueError, match="sslmode=require"):
        _enforce_tls("postgres://u:p@db.example.com:5432/x?sslmode=disable")


def test_enforce_tls_env_escape_hatch(monkeypatch):
    monkeypatch.setenv("VECTORPIN_ALLOW_INSECURE_HTTP", "1")
    _enforce_tls("postgresql://u:p@db.example.com:5432/x")


def test_enforce_tls_skips_keyword_dsn():
    """Keyword=value DSNs (``host=db port=5432 user=u``) are not URL-
    parseable; the function leaves them to libpq rather than guessing.
    """
    _enforce_tls("host=db.example.com user=u port=5432 dbname=x")


# ---- integration tests (require a reachable pgvector instance) -------------

_DEFAULT_DSN = "postgresql://postgres:mypassword@localhost:5432/vectordb"


def _pgvector_dsn() -> str | None:
    """Pick the DSN to use for integration tests.

    Order of precedence:
      1. ``VECTORPIN_TEST_PGVECTOR_URL`` env var (explicit opt-in).
      2. ``PGVECTOR_URL`` env var (shared with VectorSmuggle backend).
      3. The compose-file default (``postgres:mypassword@localhost``)
         if the connection succeeds.

    Returns ``None`` if no instance is reachable, which causes the
    integration tests to skip rather than fail.
    """
    candidates = [
        os.environ.get("VECTORPIN_TEST_PGVECTOR_URL"),
        os.environ.get("PGVECTOR_URL"),
        _DEFAULT_DSN,
    ]
    for dsn in candidates:
        if not dsn:
            continue
        try:
            with psycopg.connect(dsn, connect_timeout=2) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            return dsn
        except Exception:
            continue
    return None


@pytest.fixture(scope="module")
def pgvector_dsn():
    dsn = _pgvector_dsn()
    if dsn is None:
        pytest.skip(
            "no reachable pgvector instance "
            "(set VECTORPIN_TEST_PGVECTOR_URL or start the compose service)"
        )
    return dsn


@pytest.fixture
def pgvector_table(pgvector_dsn):
    """Create a per-test table with two rows and an empty pin column."""
    table = f"vectorpin_test_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(pgvector_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
        register_vector(conn)
        with conn.cursor() as cur:
            cur.execute(
                f"""
                CREATE TABLE "{table}" (
                    id TEXT PRIMARY KEY,
                    embedding vector(16) NOT NULL,
                    {PIN_METADATA_KEY} JSONB
                )
                """
            )
            cur.execute(
                f'INSERT INTO "{table}" (id, embedding) VALUES (%s, %s)',
                ("a", [0.1] * 16),
            )
            cur.execute(
                f'INSERT INTO "{table}" (id, embedding) VALUES (%s, %s)',
                ("b", [0.2] * 16),
            )
        yield (pgvector_dsn, table)
        with conn.cursor() as cur:
            cur.execute(f'DROP TABLE IF EXISTS "{table}"')


def test_iter_records_returns_unpinned(pgvector_table):
    dsn, table = pgvector_table
    adapter = PgVectorAdapter.connect(dsn, table)
    records = list(adapter.iter_records())
    assert {r.id for r in records} == {"a", "b"}
    assert all(r.pin is None for r in records)
    for r in records:
        assert r.vector.shape == (16,)


def test_attach_pin_and_get(pgvector_table):
    dsn, table = pgvector_table
    adapter = PgVectorAdapter.connect(dsn, table)
    signer = Signer.generate(key_id="test-key")

    rec = adapter.get("a")
    assert rec.pin is None

    pin = signer.pin(source="alpha", model="bench-model", vector=rec.vector)
    adapter.attach_pin("a", pin)

    refreshed = adapter.get("a")
    assert refreshed.pin is not None
    assert refreshed.pin.kid == "test-key"
    assert refreshed.pin.header.model == "bench-model"


def test_full_roundtrip_verifies(pgvector_table):
    dsn, table = pgvector_table
    adapter = PgVectorAdapter.connect(dsn, table)
    signer = Signer.generate(key_id="test-key")
    verifier = Verifier(public_keys={signer.key_id: signer.public_key_bytes()})

    # Sign every record (using id as the source for the test).
    for record in adapter.iter_records():
        pin = signer.pin(
            source=record.id,
            model="bench-model",
            vector=record.vector,
        )
        adapter.attach_pin(record.id, pin)

    # Re-read and verify under strict v2 rules.
    for record in adapter.iter_records():
        assert record.pin is not None
        result = verifier.verify(
            record.pin,
            source=record.id,
            vector=record.vector,
        )
        assert result.ok, result


def test_get_raises_keyerror_for_unknown_id(pgvector_table):
    dsn, table = pgvector_table
    adapter = PgVectorAdapter.connect(dsn, table)
    with pytest.raises(KeyError):
        adapter.get("does-not-exist")


def test_attach_pin_raises_keyerror_for_unknown_id(pgvector_table):
    dsn, table = pgvector_table
    adapter = PgVectorAdapter.connect(dsn, table)
    signer = Signer.generate(key_id="test-key")
    pin = signer.pin(
        source="x", model="m", vector=np.full(16, 0.1, dtype=np.float32)
    )
    with pytest.raises(KeyError):
        adapter.attach_pin("not-there", pin)


def test_loopback_dsn_does_not_trigger_tls_guard(pgvector_table):
    """Sanity: the integration connect path doesn't tripped the TLS
    guard against the loopback DSN the fixture uses."""
    dsn, table = pgvector_table
    # No env var, no sslmode — should still work because it's loopback.
    adapter = PgVectorAdapter.connect(dsn, table)
    _ = list(adapter.iter_records())


def test_invalid_table_name_rejected(pgvector_table):
    dsn, _table = pgvector_table
    with pytest.raises(ValueError, match="invalid table_name"):
        PgVectorAdapter.connect(dsn, 'bad"name')


def test_invalid_column_name_rejected(pgvector_table):
    dsn, table = pgvector_table
    with pytest.raises(ValueError, match="invalid id_column"):
        PgVectorAdapter.connect(dsn, table, id_column="drop; --")
    with pytest.raises(ValueError, match="invalid vector_column"):
        PgVectorAdapter.connect(dsn, table, vector_column="x; SELECT")
    with pytest.raises(ValueError, match="invalid pin_column"):
        PgVectorAdapter.connect(dsn, table, pin_column="not\nok")
