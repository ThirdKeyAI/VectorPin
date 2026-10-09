# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the audit-lancedb and audit-chroma CLI commands.

Each test sets up a small fixture corpus, pins every record, runs the
CLI, and asserts on the JSON summary printed to stdout. The Pinecone
audit is not exercised here because it requires live cloud creds; the
Qdrant audit has its own production deployment story.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import numpy as np
import pytest

lancedb = pytest.importorskip("lancedb")
chromadb = pytest.importorskip("chromadb")
pa = pytest.importorskip("pyarrow")

from vectorpin import Signer
from vectorpin.adapters import (
    PIN_METADATA_KEY,
    ChromaAdapter,
    LanceDBAdapter,
)
from vectorpin.cli import build_parser


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Invoke the CLI in-process. Returns (exit_code, stdout, stderr)."""
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            args = build_parser().parse_args(argv)
            code = int(args.func(args))
        except SystemExit as e:
            code = int(e.code) if isinstance(e.code, int) else 1
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def keypair_files(tmp_path: Path) -> tuple[Path, Path, str]:
    signer = Signer.generate(key_id="cli-test")
    pub = tmp_path / "cli-test.pub"
    priv = tmp_path / "cli-test.priv"
    pub.write_bytes(signer.public_key_bytes())
    priv.write_bytes(signer.private_key_bytes())
    return pub, priv, "cli-test"


@pytest.fixture
def lance_pinned_table(tmp_path: Path, keypair_files: tuple[Path, Path, str]) -> tuple[Path, str]:
    """A LanceDB table with two pinned records and one unpinned record."""
    _pub, priv, kid = keypair_files
    signer = Signer.from_private_bytes(priv.read_bytes(), key_id=kid)
    db_dir = tmp_path / "lance_db"
    db = lancedb.connect(str(db_dir))
    schema = pa.schema(
        [
            ("id", pa.string()),
            ("vector", pa.list_(pa.float32(), 16)),
            ("content", pa.string()),
            (PIN_METADATA_KEY, pa.string()),
        ]
    )
    rows = [
        {"id": "a", "vector": [0.1] * 16, "content": "alpha", PIN_METADATA_KEY: None},
        {"id": "b", "vector": [0.2] * 16, "content": "beta", PIN_METADATA_KEY: None},
        {"id": "c", "vector": [0.3] * 16, "content": "gamma", PIN_METADATA_KEY: None},
    ]
    tbl = db.create_table("audit_test", data=rows, schema=schema)
    adapter = LanceDBAdapter(tbl)
    # Pin a and b; leave c unpinned to exercise the unpinned counter.
    for record_id, source in [("a", "alpha"), ("b", "beta")]:
        rec = adapter.get(record_id)
        pin = signer.pin(source=source, model="bench-model", vector=rec.vector)
        adapter.attach_pin(record_id, pin)
    return db_dir, "audit_test"


@pytest.fixture
def chroma_pinned_collection(
    tmp_path: Path, keypair_files: tuple[Path, Path, str]
) -> tuple[Path, str]:
    _pub, priv, kid = keypair_files
    signer = Signer.from_private_bytes(priv.read_bytes(), key_id=kid)
    db_dir = tmp_path / "chroma_db"
    client = chromadb.PersistentClient(path=str(db_dir))
    coll = client.create_collection(name="audit_test")
    coll.add(
        ids=["a", "b", "c"],
        embeddings=[[0.1] * 16, [0.2] * 16, [0.3] * 16],
        metadatas=[{"text": "alpha"}, {"text": "beta"}, {"text": "gamma"}],
    )
    adapter = ChromaAdapter(coll)
    for record_id, source in [("a", "alpha"), ("b", "beta")]:
        rec = adapter.get(record_id)
        pin = signer.pin(source=source, model="bench-model", vector=rec.vector)
        adapter.attach_pin(record_id, pin)
    return db_dir, "audit_test"


# ---- audit-lancedb ----


def test_audit_lancedb_clean_run(
    lance_pinned_table: tuple[Path, str], keypair_files: tuple[Path, Path, str]
) -> None:
    db_dir, table = lance_pinned_table
    pub, _priv, kid = keypair_files
    code, stdout, _stderr = _run_cli(
        [
            "audit-lancedb",
            "--uri",
            str(db_dir),
            "--table",
            table,
            "--public-key",
            str(pub),
            "--key-id",
            kid,
            "--source-column",
            "content",
            "--allow-unpinned",
        ]
    )
    summary = json.loads(stdout)
    assert summary == {
        "table": table,
        "total": 3,
        "pinned": 2,
        "verified_ok": 2,
        "verification_failed": 0,
        "unpinned": 1,
    }
    assert code == 0


def test_audit_lancedb_detects_tamper(
    lance_pinned_table: tuple[Path, str], keypair_files: tuple[Path, Path, str]
) -> None:
    """Mutate one vector after pinning; audit must report a verification failure."""
    db_dir, table = lance_pinned_table
    pub, _priv, kid = keypair_files

    # Surgically corrupt record 'a'. We rewrite the table with one
    # vector mutated; the Pin in the metadata column stays, so the
    # vec_hash mismatch will fire on read.
    db = lancedb.connect(str(db_dir))
    tbl = db.open_table(table)
    bad_vec = ", ".join("100.0" for _ in range(16))
    tbl.update(where="id = 'a'", values_sql={"vector": f"[{bad_vec}]"})

    code, stdout, stderr = _run_cli(
        [
            "audit-lancedb",
            "--uri",
            str(db_dir),
            "--table",
            table,
            "--public-key",
            str(pub),
            "--key-id",
            kid,
            "--source-column",
            "content",
            "--allow-unpinned",
        ]
    )
    summary = json.loads(stdout)
    assert summary["verification_failed"] == 1
    assert summary["verified_ok"] == 1
    assert summary["unpinned"] == 1
    assert "vector_tampered" in stderr
    assert "FAIL a" in stderr
    assert code == 1


def test_audit_lancedb_unpinned_fails_closed_by_default(
    lance_pinned_table: tuple[Path, str], keypair_files: tuple[Path, Path, str]
) -> None:
    """VP-2: without --allow-unpinned an unpinned record fails the run
    and is named on stderr, so pin stripping cannot hide as 'unpinned'."""
    db_dir, table = lance_pinned_table
    pub, _priv, kid = keypair_files
    code, stdout, stderr = _run_cli(
        [
            "audit-lancedb",
            "--uri",
            str(db_dir),
            "--table",
            table,
            "--public-key",
            str(pub),
            "--key-id",
            kid,
            "--source-column",
            "content",
        ]
    )
    summary = json.loads(stdout)
    assert summary["unpinned"] == 1
    assert summary["verification_failed"] == 1
    assert "FAIL c [unpinned]" in stderr
    assert code == 1


def test_audit_lancedb_stripped_pin_is_parse_error_not_unpinned(
    lance_pinned_table: tuple[Path, str], keypair_files: tuple[Path, Path, str]
) -> None:
    """VP-2: blanking the pin field (what an attacker who can rewrite the
    vector would do) is a parse_error even with --allow-unpinned."""
    db_dir, table = lance_pinned_table
    pub, _priv, kid = keypair_files
    db = lancedb.connect(str(db_dir))
    tbl = db.open_table(table)
    tbl.update(where="id = 'a'", values={PIN_METADATA_KEY: "   "})
    code, stdout, stderr = _run_cli(
        [
            "audit-lancedb",
            "--uri",
            str(db_dir),
            "--table",
            table,
            "--public-key",
            str(pub),
            "--key-id",
            kid,
            "--allow-unpinned",
        ]
    )
    summary = json.loads(stdout)
    assert summary["unpinned"] == 1  # only 'c'
    assert summary["verification_failed"] == 1
    assert "FAIL a [parse_error]" in stderr
    assert code == 1


# ---- audit-chroma ----


def test_audit_chroma_clean_run(
    chroma_pinned_collection: tuple[Path, str], keypair_files: tuple[Path, Path, str]
) -> None:
    db_dir, collection = chroma_pinned_collection
    pub, _priv, kid = keypair_files
    code, stdout, _stderr = _run_cli(
        [
            "audit-chroma",
            "--path",
            str(db_dir),
            "--collection",
            collection,
            "--public-key",
            str(pub),
            "--key-id",
            kid,
            "--source-metadata-key",
            "text",
            "--allow-unpinned",
        ]
    )
    summary = json.loads(stdout)
    assert summary == {
        "collection": collection,
        "total": 3,
        "pinned": 2,
        "verified_ok": 2,
        "verification_failed": 0,
        "unpinned": 1,
    }
    assert code == 0


def test_audit_chroma_signature_only(
    chroma_pinned_collection: tuple[Path, str], keypair_files: tuple[Path, Path, str]
) -> None:
    """Without --source-metadata-key the audit verifies signature + vector only."""
    db_dir, collection = chroma_pinned_collection
    pub, _priv, kid = keypair_files
    code, stdout, _stderr = _run_cli(
        [
            "audit-chroma",
            "--path",
            str(db_dir),
            "--collection",
            collection,
            "--public-key",
            str(pub),
            "--key-id",
            kid,
            "--allow-unpinned",
        ]
    )
    summary = json.loads(stdout)
    assert summary["verification_failed"] == 0
    assert summary["verified_ok"] == 2
    assert code == 0


def test_audit_chroma_requires_path_or_host(
    keypair_files: tuple[Path, Path, str], tmp_path: Path
) -> None:
    pub, _priv, kid = keypair_files
    code, _stdout, stderr = _run_cli(
        [
            "audit-chroma",
            "--collection",
            "nope",
            "--public-key",
            str(pub),
            "--key-id",
            kid,
        ]
    )
    assert code != 0
    assert "audit-chroma requires" in stderr


# ---- argparse wiring sanity check ----


def test_parser_registers_new_audit_commands() -> None:
    parser = build_parser()
    # parse_args succeeds for the help-equivalent shape of each new command.
    for cmd in ("audit-lancedb", "audit-chroma"):
        with pytest.raises(SystemExit):
            parser.parse_args([cmd, "--help"])


# Defensive: the unused-import linter shouldn't complain about np in this file.
_NUMPY_VERSION = np.__version__
