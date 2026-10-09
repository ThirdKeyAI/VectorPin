# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Adapter protocol shared by every vector store backend."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import numpy as np

from vectorpin.attestation import Pin

if TYPE_CHECKING:
    from vectorpin.verifier import VerificationResult, Verifier

PIN_METADATA_KEY = "vectorpin"
"""Name of the metadata field that holds the serialized Pin JSON.

Backends that don't have free-form metadata MUST find another way to
attach this value. We do not support storing pins separately from the
vectors they cover — provenance must travel with the data.
"""


@dataclass(frozen=True)
class PinnedRecord:
    """A vector + its attached Pin + arbitrary other metadata.

    ``pin`` is ``None`` in exactly two situations, distinguished by
    ``parse_error``:

    * the record carries no pin field at all (``parse_error is None``) —
      an *unpinned* record;
    * the record carries a pin field that failed to parse, including an
      empty or whitespace-only value (``parse_error`` holds the reason).

    Adapters never raise on a malformed pin: raising from inside a
    generator finalizes it, which would silently end the audit at the
    first bad row. The error travels with the record instead.
    """

    id: str
    vector: np.ndarray
    pin: Pin | None
    metadata: dict[str, Any]
    parse_error: str | None = None


@dataclass(frozen=True)
class VerifiedRecord:
    """A record paired with the outcome of verifying it (read-path wrapper)."""

    record: PinnedRecord
    result: VerificationResult

    @property
    def ok(self) -> bool:
        return self.result.ok

    def __bool__(self) -> bool:
        return self.result.ok


def parse_pin_field(raw: Any) -> tuple[Pin | None, str | None]:
    """Turn a stored pin field into ``(pin, parse_error)`` without raising.

    * ``None`` means the field is absent: ``(None, None)`` — unpinned.
    * A ``str`` is parsed as pin JSON; a ``dict`` through ``Pin.from_dict``.
    * An empty / whitespace-only string or an empty dict is a parse
      error, not an unpinned record: an attacker who can edit the row
      can blank the field as easily as delete it, and the audit must
      not treat the two differently.
    """
    if raw is None:
        return None, None
    try:
        if isinstance(raw, str):
            if not raw.strip():
                return None, "pin field is empty"
            return Pin.from_json(raw), None
        if isinstance(raw, dict):
            if not raw:
                return None, "pin field is an empty object"
            return Pin.from_dict(raw), None
        return None, f"pin field has unsupported type {type(raw).__name__}"
    except Exception as e:  # adapters must never raise per row
        return None, f"{type(e).__name__}: {e}"


def vector_from_store(values: Any, *, native_dtype: Any = None) -> np.ndarray:
    """Build the verifier-facing array for a stored vector.

    The array must carry the store's *native* precision, never a
    coerced one: the verifier refuses a vector wider than the pinned
    dtype, and a narrower one would not hash equal, so the dtype the
    audit sees has to be the dtype the store persists.

    ``native_dtype`` is the element type the backend persists, learned
    from its schema (LanceDB, pgvector) or from the backend's storage
    format (Chroma, Qdrant, Pinecone persist single precision). Clients
    routinely deliver those values as 64-bit Python floats or float64
    arrays, so the transport width is not evidence of the storage width.
    When the delivered values are wider than ``native_dtype`` they are
    narrowed only if that is exact; values that do not survive the
    round trip prove the backend holds more precision than declared,
    and that is an error rather than a silent cast.

    With no ``native_dtype`` an ndarray keeps its own dtype and a plain
    sequence is taken as float64, the widest interpretation, which the
    verifier rejects for an f32 pin rather than silently narrowing.
    """
    if native_dtype is None:
        arr = values if isinstance(values, np.ndarray) else np.asarray(values, dtype=np.float64)
    else:
        target = np.dtype(native_dtype)
        arr = np.asarray(values)
        if arr.dtype != target:
            if arr.dtype.kind != "f":
                arr = arr.astype(target)
            elif arr.dtype.itemsize > target.itemsize:
                narrowed = arr.astype(target)
                if not np.array_equal(narrowed.astype(arr.dtype), arr):
                    raise ValueError(
                        f"store returned {arr.dtype} values that are not exactly "
                        f"representable in its declared native dtype {target}; the "
                        "backend persists more precision than the adapter assumes"
                    )
                arr = narrowed
            else:
                arr = arr.astype(target)
    if arr.ndim != 1:
        raise ValueError(f"vector has non-1D shape {arr.shape}")
    return arr


class BaseAdapter(ABC):
    """Read/write interface that adapters implement.

    Adapters must be lazy: an adapter that wraps Qdrant should not
    require Qdrant to be importable just to construct the class. Push
    backend imports into `__init__` of the concrete adapter, not into
    module top level.
    """

    @abstractmethod
    def iter_records(self, *, batch_size: int = 256) -> Iterator[PinnedRecord]:
        """Yield every record in the collection, with its pin if present.

        Implementations MUST NOT raise on a malformed pin; they yield a
        record with ``pin=None`` and ``parse_error`` set so iteration
        continues past the bad row.
        """

    @abstractmethod
    def get(self, record_id: str) -> PinnedRecord:
        """Fetch a single record by id."""

    @abstractmethod
    def attach_pin(self, record_id: str, pin: Pin) -> None:
        """Store a Pin in the metadata field of an existing record."""

    # ---- verifying read wrappers -------------------------------------

    def get_verified(
        self,
        record_id: str,
        verifier: Verifier,
        *,
        source_key: str | None = None,
        allow_unpinned: bool = False,
        enforce_record_id: bool = True,
        expected_model: str | None = None,
        expected_model_hash: str | None = None,
        expected_collection_id: str | None = None,
        expected_tenant_id: str | None = None,
    ) -> VerifiedRecord:
        """Fetch one record and verify it in the same call.

        This is the read-path hook: a retrieval layer that only ever
        reads through ``get_verified`` / ``iter_verified`` never hands a
        tampered, unpinned, or unparseable record to a model without a
        structured verdict attached. Never raises on record content.
        """
        record = self.get(record_id)
        return VerifiedRecord(
            record,
            verify_record(
                record,
                verifier,
                source_key=source_key,
                allow_unpinned=allow_unpinned,
                enforce_record_id=enforce_record_id,
                expected_model=expected_model,
                expected_model_hash=expected_model_hash,
                expected_collection_id=expected_collection_id,
                expected_tenant_id=expected_tenant_id,
            ),
        )

    def iter_verified(
        self,
        verifier: Verifier,
        *,
        batch_size: int = 256,
        source_key: str | None = None,
        allow_unpinned: bool = False,
        enforce_record_id: bool = True,
        expected_model: str | None = None,
        expected_model_hash: str | None = None,
        expected_collection_id: str | None = None,
        expected_tenant_id: str | None = None,
    ) -> Iterator[VerifiedRecord]:
        """Walk the collection, verifying every record as it is read."""
        for record in self.iter_records(batch_size=batch_size):
            yield VerifiedRecord(
                record,
                verify_record(
                    record,
                    verifier,
                    source_key=source_key,
                    allow_unpinned=allow_unpinned,
                    enforce_record_id=enforce_record_id,
                    expected_model=expected_model,
                    expected_model_hash=expected_model_hash,
                    expected_collection_id=expected_collection_id,
                    expected_tenant_id=expected_tenant_id,
                ),
            )


def verify_record(
    record: PinnedRecord,
    verifier: Verifier,
    *,
    source_key: str | None = None,
    allow_unpinned: bool = False,
    enforce_record_id: bool = True,
    expected_model: str | None = None,
    expected_model_hash: str | None = None,
    expected_collection_id: str | None = None,
    expected_tenant_id: str | None = None,
) -> VerificationResult:
    """Verify a ``PinnedRecord`` with the audit's default policy.

    * A parse error on the stored pin is ``PARSE_ERROR``.
    * An unpinned record is ``PARSE_ERROR`` unless ``allow_unpinned``.
    * ``source_key`` names the metadata field holding the source text;
      a missing field is ``SOURCE_MISMATCH``.
    * When the pin carries ``vectorpin.record_id`` and
      ``enforce_record_id`` is set, it must equal ``record.id``.
    * ``expected_*`` are forwarded to ``Verifier.verify``.
    """
    from vectorpin.verifier import VerificationResult, VerifyError

    if record.parse_error is not None:
        return VerificationResult(
            False, VerifyError.PARSE_ERROR, f"stored pin is malformed: {record.parse_error}"
        )
    if record.pin is None:
        if allow_unpinned:
            return VerificationResult(True, VerifyError.OK, "record is unpinned (allowed)")
        return VerificationResult(
            False, VerifyError.PARSE_ERROR, "record has no pin (unpinned records fail closed)"
        )
    kwargs: dict[str, Any] = {"vector": record.vector}
    if source_key is not None:
        src = record.metadata.get(source_key)
        if src is None:
            return VerificationResult(
                False,
                VerifyError.SOURCE_MISMATCH,
                f"record has no {source_key!r} field to verify the source against",
            )
        kwargs["source"] = str(src)
    if enforce_record_id and "vectorpin.record_id" in record.pin.header.extra:
        kwargs["expected_record_id"] = record.id
    if expected_model is not None:
        kwargs["expected_model"] = expected_model
    if expected_model_hash is not None:
        kwargs["expected_model_hash"] = expected_model_hash
    if expected_collection_id is not None:
        kwargs["expected_collection_id"] = expected_collection_id
    if expected_tenant_id is not None:
        kwargs["expected_tenant_id"] = expected_tenant_id
    return verifier.verify(record.pin, **kwargs)
