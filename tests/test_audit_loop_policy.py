# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Audit-loop policy tests driven by an in-memory adapter.

These pin the fail-closed contract of ``vectorpin.cli._audit_loop``
without needing a real vector store:

* VP-2: unpinned records fail unless ``allow_unpinned``; an empty pin
  field is a ``parse_error``; per-record ids are printed.
* VP-3: ``vectorpin.record_id`` is enforced against the record it sits
  on; collection / tenant / model / model_hash expectations are enforced.
* VP-7: a malformed pin in the middle of the corpus does not stop the
  walk — every later record is still examined.
* Collection manifest: deletion, insertion and pin stripping are caught.
* Signed summary: the printed JSON carries a verifiable signature.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from vectorpin import Signer, Verifier, build_manifest, verify_audit_summary
from vectorpin.adapters.base import BaseAdapter, PinnedRecord, parse_pin_field
from vectorpin.attestation import Pin
from vectorpin.cli import _audit_loop


class MemoryAdapter(BaseAdapter):
    """Minimal adapter over a dict of raw rows (vector, pin field, metadata)."""

    def __init__(self, rows: dict[str, dict[str, Any]]):
        self.rows = rows

    def iter_records(self, *, batch_size: int = 256) -> Iterator[PinnedRecord]:
        for rid, row in self.rows.items():
            pin, err = parse_pin_field(row.get("pin"))
            yield PinnedRecord(
                id=rid,
                vector=row["vector"],
                pin=pin,
                metadata=dict(row.get("metadata", {})),
                parse_error=err,
            )

    def get(self, record_id: str) -> PinnedRecord:
        for rec in self.iter_records():
            if rec.id == record_id:
                return rec
        raise KeyError(record_id)

    def attach_pin(self, record_id: str, pin: Pin) -> None:
        self.rows[record_id]["pin"] = pin.to_json()


@pytest.fixture
def signer() -> Signer:
    return Signer.generate(key_id="audit-key")


@pytest.fixture
def verifier(signer: Signer) -> Verifier:
    return Verifier({signer.key_id: signer.public_key_bytes()})


def _vec(seed: int) -> np.ndarray:
    return np.random.default_rng(seed).normal(size=16).astype(np.float32)


def _corpus(signer: Signer, n: int = 3, *, with_record_id: bool = True) -> MemoryAdapter:
    rows: dict[str, dict[str, Any]] = {}
    for i in range(n):
        rid = f"rec-{i}"
        v = _vec(i)
        extra = {"vectorpin.record_id": rid} if with_record_id else None
        pin = signer.pin(source=f"text {i}", model="m", vector=v, extra=extra)
        rows[rid] = {"vector": v, "pin": pin.to_json(), "metadata": {"text": f"text {i}"}}
    return MemoryAdapter(rows)


def _run(adapter: MemoryAdapter, verifier: Verifier, **kwargs: Any) -> tuple[int, dict, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = _audit_loop(
            adapter.iter_records(),
            verifier,
            source_column=kwargs.pop("source_column", "text"),
            label_field="collection",
            label_value=kwargs.pop("label_value", "c1"),
            **kwargs,
        )
    return code, json.loads(out.getvalue()), err.getvalue()


# ---- VP-2 ------------------------------------------------------------------


def test_clean_corpus_passes(signer: Signer, verifier: Verifier) -> None:
    code, summary, _ = _run(_corpus(signer), verifier)
    assert code == 0
    assert summary["verified_ok"] == 3 and summary["verification_failed"] == 0


def test_unpinned_record_fails_by_default_and_is_named(
    signer: Signer, verifier: Verifier
) -> None:
    adapter = _corpus(signer)
    adapter.rows["rec-1"]["pin"] = None
    code, summary, err = _run(adapter, verifier)
    assert code == 1
    assert summary["unpinned"] == 1
    assert summary["verification_failed"] == 1
    assert "FAIL rec-1 [unpinned]" in err


def test_allow_unpinned_opts_in(signer: Signer, verifier: Verifier) -> None:
    adapter = _corpus(signer)
    adapter.rows["rec-1"]["pin"] = None
    code, summary, _ = _run(adapter, verifier, allow_unpinned=True)
    assert code == 0
    assert summary["unpinned"] == 1 and summary["verification_failed"] == 0


@pytest.mark.parametrize("blank", ["", "   ", "\n"])
def test_empty_pin_field_is_parse_error_even_when_unpinned_allowed(
    signer: Signer, verifier: Verifier, blank: str
) -> None:
    adapter = _corpus(signer)
    adapter.rows["rec-2"]["pin"] = blank
    code, summary, err = _run(adapter, verifier, allow_unpinned=True)
    assert code == 1
    assert summary["unpinned"] == 0
    assert "FAIL rec-2 [parse_error]" in err


def test_empty_dict_pin_is_parse_error() -> None:
    pin, err = parse_pin_field({})
    assert pin is None and err is not None


# ---- VP-7 ------------------------------------------------------------------


def test_malformed_pin_mid_corpus_does_not_stop_the_walk(
    signer: Signer, verifier: Verifier
) -> None:
    adapter = _corpus(signer, n=5)
    adapter.rows["rec-1"]["pin"] = '{"v": 2, "garbage": true'
    # Tamper a *later* record so we can prove it was examined.
    adapter.rows["rec-4"]["vector"] = adapter.rows["rec-4"]["vector"] + np.float32(1e-3)
    code, summary, err = _run(adapter, verifier)
    assert code == 1
    assert summary["total"] == 5
    assert summary["verification_failed"] == 2
    assert "FAIL rec-1 [parse_error]" in err
    assert "FAIL rec-4 [vector_tampered]" in err


def test_adapter_exception_is_reported_and_marks_summary_aborted(verifier: Verifier) -> None:
    def broken() -> Iterator[PinnedRecord]:
        yield PinnedRecord(id="a", vector=_vec(0), pin=None, metadata={})
        raise RuntimeError("connection lost")

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = _audit_loop(
            broken(),
            verifier,
            source_column=None,
            label_field="t",
            label_value="x",
            allow_unpinned=True,
        )
    summary = json.loads(out.getvalue())
    assert code == 1
    assert "connection lost" in summary["aborted"]
    assert "[adapter_error]" in err.getvalue()


# ---- VP-3 ------------------------------------------------------------------


def test_pin_shuffle_across_records_is_caught(signer: Signer, verifier: Verifier) -> None:
    """Copy (vector, pin, source) from rec-0 onto rec-1's slot."""
    adapter = _corpus(signer)
    adapter.rows["rec-1"] = dict(adapter.rows["rec-0"])
    code, summary, err = _run(adapter, verifier)
    assert code == 1
    assert "FAIL rec-1 [record_mismatch]" in err
    assert summary["verification_failed"] == 1


def test_record_id_check_can_be_disabled(signer: Signer, verifier: Verifier) -> None:
    adapter = _corpus(signer)
    adapter.rows["rec-1"] = dict(adapter.rows["rec-0"])
    code, _, _ = _run(adapter, verifier, enforce_record_id=False)
    assert code == 0


def test_pins_without_record_id_warn_once(signer: Signer, verifier: Verifier) -> None:
    code, _, err = _run(_corpus(signer, with_record_id=False), verifier)
    assert code == 0
    assert err.count("carries no vectorpin.record_id") == 1


def test_collection_and_tenant_expectations_enforced(signer: Signer, verifier: Verifier) -> None:
    v = _vec(7)
    pin = signer.pin(
        source="t",
        model="m",
        vector=v,
        extra={"vectorpin.collection_id": "col-A", "vectorpin.tenant_id": "ten-1"},
    )
    adapter = MemoryAdapter({"r": {"vector": v, "pin": pin.to_json(), "metadata": {"text": "t"}}})
    assert _run(adapter, verifier, collection_id="col-A", tenant_id="ten-1")[0] == 0
    code, _, err = _run(adapter, verifier, collection_id="col-B")
    assert code == 1 and "[collection_mismatch]" in err
    code, _, err = _run(adapter, verifier, tenant_id="ten-2")
    assert code == 1 and "[tenant_mismatch]" in err
    # A pin that carries no collection binding fails when one is expected.
    bare = signer.pin(source="t", model="m", vector=v)
    adapter.rows["r"]["pin"] = bare.to_json()
    code, _, err = _run(adapter, verifier, collection_id="col-A")
    assert code == 1 and "[collection_mismatch]" in err


def test_expected_model_and_model_hash_enforced(signer: Signer, verifier: Verifier) -> None:
    v = _vec(8)
    mh = "sha256:" + "a" * 64
    pin = signer.pin(source="t", model="good-model", vector=v, model_hash=mh)
    adapter = MemoryAdapter({"r": {"vector": v, "pin": pin.to_json(), "metadata": {"text": "t"}}})
    assert _run(adapter, verifier, expected_model="good-model", expected_model_hash=mh)[0] == 0
    code, _, err = _run(adapter, verifier, expected_model="other-model")
    assert code == 1 and "[model_mismatch]" in err
    code, _, err = _run(adapter, verifier, expected_model_hash="sha256:" + "b" * 64)
    assert code == 1 and "[model_mismatch]" in err


def test_missing_source_column_is_a_failure(signer: Signer, verifier: Verifier) -> None:
    adapter = _corpus(signer)
    del adapter.rows["rec-0"]["metadata"]["text"]
    code, _, err = _run(adapter, verifier)
    assert code == 1
    assert "FAIL rec-0 [source_mismatch]" in err


# ---- collection manifest ---------------------------------------------------


def _entries(adapter: MemoryAdapter) -> list[tuple[str, str]]:
    return [
        (rec.id, rec.pin.header.vec_hash if rec.pin is not None else "")
        for rec in adapter.iter_records()
    ]


def test_manifest_matches_untouched_corpus(signer: Signer, verifier: Verifier) -> None:
    adapter = _corpus(signer)
    manifest = build_manifest(signer, "c1", _entries(adapter))
    code, summary, _ = _run(adapter, verifier, manifest=manifest, collection_id=None)
    assert code == 0
    assert summary["manifest"] == "ok"


def test_manifest_catches_deleted_record(signer: Signer, verifier: Verifier) -> None:
    adapter = _corpus(signer)
    manifest = build_manifest(signer, "c1", _entries(adapter))
    del adapter.rows["rec-2"]
    code, summary, err = _run(adapter, verifier, manifest=manifest)
    assert code == 1
    assert summary["manifest"] == "count_mismatch"
    assert "FAIL <manifest> [count_mismatch]" in err


def test_manifest_catches_inserted_record_even_when_unpinned_allowed(
    signer: Signer, verifier: Verifier
) -> None:
    adapter = _corpus(signer)
    manifest = build_manifest(signer, "c1", _entries(adapter))
    adapter.rows["rec-new"] = {"vector": _vec(99), "pin": None, "metadata": {"text": "x"}}
    code, summary, _ = _run(adapter, verifier, manifest=manifest, allow_unpinned=True)
    assert code == 1
    assert summary["manifest"] == "count_mismatch"


def test_manifest_catches_stripped_pin_replaced_by_record_swap(
    signer: Signer, verifier: Verifier
) -> None:
    """Same count, different set: a record re-pinned under a different
    (still valid) pin changes the Merkle root."""
    adapter = _corpus(signer)
    manifest = build_manifest(signer, "c1", _entries(adapter))
    v = _vec(5)
    adapter.rows["rec-1"] = {
        "vector": v,
        "pin": signer.pin(
            source="t", model="m", vector=v, extra={"vectorpin.record_id": "rec-1"}
        ).to_json(),
        "metadata": {"text": "t"},
    }
    code, summary, _ = _run(adapter, verifier, manifest=manifest)
    assert code == 1
    assert summary["manifest"] == "root_mismatch"


def test_write_manifest_then_verify_round_trip(
    signer: Signer, verifier: Verifier, tmp_path: Path
) -> None:
    adapter = _corpus(signer)
    path = tmp_path / "manifest.json"
    code, summary, _ = _run(adapter, verifier, write_manifest=(path, signer))
    assert code == 0 and summary["manifest_written"] == str(path)
    from vectorpin import CollectionManifest

    manifest = CollectionManifest.from_json(path.read_text())
    assert manifest.count == 3 and manifest.collection_id == "c1"
    code, summary, _ = _run(adapter, verifier, manifest=manifest)
    assert code == 0 and summary["manifest"] == "ok"


# ---- signed summary ---------------------------------------------------------


def test_signed_summary_verifies_and_detects_edits(signer: Signer, verifier: Verifier) -> None:
    code, summary, _ = _run(_corpus(signer), verifier, summary_signer=signer)
    assert code == 0
    assert verify_audit_summary(summary, verifier).ok
    forged = dict(summary)
    forged["verification_failed"] = 0
    forged["verified_ok"] = 9999
    assert not verify_audit_summary(forged, verifier).ok
    unsigned = {k: v for k, v in summary.items() if k != "summary_sig"}
    assert verify_audit_summary(unsigned, verifier).error.value == "parse_error"
