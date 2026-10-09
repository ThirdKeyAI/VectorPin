# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Verifying read wrappers on BaseAdapter (get_verified / iter_verified).

The read path is where a tampered vector would otherwise reach a model.
Every adapter inherits these wrappers, so a retrieval layer can refuse
to serve a record without a verdict attached — and the wrappers never
raise on record content.
"""

from __future__ import annotations

from collections.abc import Iterator

import numpy as np
import pytest

from vectorpin import Signer, Verifier, VerifyError
from vectorpin.adapters.base import BaseAdapter, PinnedRecord, parse_pin_field
from vectorpin.attestation import Pin


class MemoryAdapter(BaseAdapter):
    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}

    def iter_records(self, *, batch_size: int = 256) -> Iterator[PinnedRecord]:
        for rid, row in self.rows.items():
            pin, err = parse_pin_field(row.get("pin"))
            yield PinnedRecord(rid, row["vector"], pin, dict(row.get("meta", {})), err)

    def get(self, record_id: str) -> PinnedRecord:
        row = self.rows[record_id]
        pin, err = parse_pin_field(row.get("pin"))
        return PinnedRecord(record_id, row["vector"], pin, dict(row.get("meta", {})), err)

    def attach_pin(self, record_id: str, pin: Pin) -> None:
        self.rows[record_id]["pin"] = pin.to_json()


@pytest.fixture
def world() -> tuple[MemoryAdapter, Signer, Verifier]:
    signer = Signer.generate(key_id="k")
    verifier = Verifier({"k": signer.public_key_bytes()})
    adapter = MemoryAdapter()
    for i in range(3):
        v = np.full(8, 0.1 * (i + 1), dtype=np.float32)
        adapter.rows[f"r{i}"] = {"vector": v, "meta": {"text": f"t{i}"}}
        adapter.attach_pin(
            f"r{i}",
            signer.pin(
                source=f"t{i}", model="m", vector=v, extra={"vectorpin.record_id": f"r{i}"}
            ),
        )
    return adapter, signer, verifier


def test_get_verified_ok(world) -> None:
    adapter, _, verifier = world
    vr = adapter.get_verified("r0", verifier, source_key="text")
    assert vr and vr.ok and vr.record.id == "r0"


def test_get_verified_catches_tamper(world) -> None:
    adapter, _, verifier = world
    adapter.rows["r1"]["vector"] = adapter.rows["r1"]["vector"] + np.float32(1e-3)
    vr = adapter.get_verified("r1", verifier)
    assert not vr
    assert vr.result.error is VerifyError.VECTOR_TAMPERED


def test_get_verified_unpinned_fails_closed_unless_allowed(world) -> None:
    adapter, _, verifier = world
    adapter.rows["r2"]["pin"] = None
    assert not adapter.get_verified("r2", verifier)
    assert adapter.get_verified("r2", verifier, allow_unpinned=True).ok


def test_get_verified_malformed_pin_is_structured(world) -> None:
    adapter, _, verifier = world
    adapter.rows["r2"]["pin"] = "{not json"
    vr = adapter.get_verified("r2", verifier)
    assert vr.result.error is VerifyError.PARSE_ERROR
    assert "malformed" in vr.result.detail


def test_get_verified_enforces_record_id(world) -> None:
    adapter, _, verifier = world
    adapter.rows["r2"]["pin"] = adapter.rows["r0"]["pin"]
    adapter.rows["r2"]["vector"] = adapter.rows["r0"]["vector"]
    vr = adapter.get_verified("r2", verifier)
    assert vr.result.error is VerifyError.RECORD_MISMATCH


def test_iter_verified_walks_everything(world) -> None:
    adapter, _, verifier = world
    adapter.rows["r1"]["vector"] = adapter.rows["r1"]["vector"] * np.float32(1.0001)
    verdicts = {vr.record.id: vr.ok for vr in adapter.iter_verified(verifier, source_key="text")}
    assert verdicts == {"r0": True, "r1": False, "r2": True}
