# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Signed collection manifests and signed audit summaries.

Per-record pins attest to individual vectors; they say nothing about
the *set* of records. An attacker with write access can delete a
pinned record, insert an unpinned one, or blank a pin field, and no
per-record signature changes. A ``CollectionManifest`` closes that gap:
it commits, under an Ed25519 signature, to the record count and to a
Merkle root over ``record_id -> vec_hash`` for every record in the
collection at ingestion time. The audit recomputes the root from what
the store holds now and compares.

The manifest is meant to live out-of-band (object storage, a CI
artifact, a transparency log) where the database administrator cannot
rewrite it alongside the data.

The same signing primitive protects the audit CLI's own JSON summary,
so a host that controls both the database and the audit job cannot
forge a clean report without the summary-signing key.

Both message types are signed over ``domain_tag || canonical_json`` with
tags distinct from the pin tag, so a signature on one can never be
replayed as another.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from vectorpin.attestation import (
    _TS_RE,
    _b64,
    _b64dec,
    _check_nfc,
    _check_string_safe,
    _check_ts_calendar,
)
from vectorpin.hash import hash_bytes

if TYPE_CHECKING:
    from vectorpin.signer import Signer
    from vectorpin.verifier import Verifier

MANIFEST_VERSION = 1
MANIFEST_DOMAIN_TAG = b"vectorpin/manifest/v1\x00"
AUDIT_SUMMARY_DOMAIN_TAG = b"vectorpin/audit-summary/v1\x00"

# Leaf / interior node prefixes make the tree second-preimage resistant
# (a leaf can never be confused with a concatenation of two children).
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

_MAX_MANIFEST_JSON_BYTES = 65536
_MAX_COLLECTION_ID_BYTES = 1024
_HASH_PREFIX = "sha256:"


class ManifestError(Enum):
    """Distinct outcomes of :func:`verify_manifest`."""

    OK = "ok"
    PARSE_ERROR = "parse_error"
    UNKNOWN_KEY = "unknown_key"
    SIGNATURE_INVALID = "signature_invalid"
    COLLECTION_MISMATCH = "collection_mismatch"
    COUNT_MISMATCH = "count_mismatch"
    ROOT_MISMATCH = "root_mismatch"


@dataclass(frozen=True)
class ManifestResult:
    ok: bool
    error: ManifestError
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ok


# ---- Merkle root -----------------------------------------------------------


def _leaf(record_id: str, vec_hash: str) -> bytes:
    return hashlib.sha256(
        _LEAF_PREFIX + record_id.encode("utf-8") + b"\x00" + vec_hash.encode("utf-8")
    ).digest()


def merkle_root(entries: Iterable[tuple[str, str]]) -> str:
    """Merkle root over ``(record_id, vec_hash)`` pairs, as ``sha256:<hex>``.

    Entries are sorted by ``record_id`` (code-point order) so the root
    is independent of iteration order. ``vec_hash`` is the pin's
    ``vec_hash`` for a pinned record and the empty string for an
    unpinned one, so stripping a pin changes the root just as deleting
    the row does. Duplicate ids are an error: the root must describe a
    set. An odd level duplicates its last node; the empty set hashes to
    ``SHA-256("")``.
    """
    items = sorted(entries, key=lambda e: e[0])
    for i in range(1, len(items)):
        if items[i][0] == items[i - 1][0]:
            raise ValueError(f"duplicate record id in manifest entries: {items[i][0]!r}")
    for rid, vh in items:
        if not isinstance(rid, str) or not isinstance(vh, str):
            raise TypeError("manifest entries must be (str, str) pairs")
    if not items:
        return hash_bytes(b"")
    level = [_leaf(rid, vh) for rid, vh in items]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [
            hashlib.sha256(_NODE_PREFIX + level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return f"{_HASH_PREFIX}{level[0].hex()}"


# ---- canonical JSON signing shared by both message types -------------------


def _canonical_json(d: dict[str, Any]) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _now_ts() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_ts(ts: Any, field_name: str) -> str:
    if not isinstance(ts, str) or not _TS_RE.match(ts):
        raise ValueError(f"{field_name} must match 'YYYY-MM-DDTHH:MM:SSZ' exactly")
    _check_ts_calendar(ts, field_name)
    return ts


def _validate_id(value: Any, field_name: str, limit: int) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    if len(value.encode("utf-8", errors="surrogatepass")) > limit:
        raise ValueError(f"{field_name} exceeds maximum {limit} bytes")
    _check_string_safe(value, field_name)
    _check_nfc(value, field_name)
    return value


# ---- collection manifest ---------------------------------------------------


@dataclass(frozen=True)
class CollectionManifest:
    """Signed commitment to a collection's record set.

    Fields under the signature: ``v``, ``collection_id``, ``count``,
    ``merkle_root``, ``ts``, ``kid``. ``sig`` is the Ed25519 signature
    over ``MANIFEST_DOMAIN_TAG || canonical_json(those fields)``.
    """

    collection_id: str
    count: int
    merkle_root: str
    ts: str
    kid: str
    sig: bytes
    v: int = MANIFEST_VERSION

    def signed_dict(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "collection_id": self.collection_id,
            "count": self.count,
            "merkle_root": self.merkle_root,
            "ts": self.ts,
            "kid": self.kid,
        }

    def canonical_payload(self) -> bytes:
        return _canonical_json(self.signed_dict())

    def to_dict(self) -> dict[str, Any]:
        d = self.signed_dict()
        d["sig"] = _b64(self.sig)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CollectionManifest:
        if not isinstance(d, dict):
            raise ValueError("manifest must be a JSON object")
        allowed = {"v", "collection_id", "count", "merkle_root", "ts", "kid", "sig"}
        unknown = set(d) - allowed
        if unknown:
            raise ValueError(f"manifest contains unknown field(s): {sorted(unknown)}")
        v = d.get("v")
        if not isinstance(v, int) or isinstance(v, bool) or v != MANIFEST_VERSION:
            raise ValueError(f"unsupported manifest version {v!r}")
        count = d.get("count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("count must be a non-negative integer")
        root = d.get("merkle_root")
        if (
            not isinstance(root, str)
            or not root.startswith(_HASH_PREFIX)
            or len(root) != len(_HASH_PREFIX) + 64
            or any(c not in "0123456789abcdef" for c in root[len(_HASH_PREFIX) :])
        ):
            raise ValueError("merkle_root must match 'sha256:<64 hex chars>'")
        sig_raw = d.get("sig")
        if not isinstance(sig_raw, str) or len(sig_raw) > 256:
            raise ValueError("sig must be a base64url string")
        sig = _b64dec(sig_raw)
        if len(sig) != 64:
            raise ValueError("sig must decode to exactly 64 bytes")
        return cls(
            collection_id=_validate_id(
                d.get("collection_id"), "collection_id", _MAX_COLLECTION_ID_BYTES
            ),
            count=count,
            merkle_root=root,
            ts=_validate_ts(d.get("ts"), "ts"),
            kid=_validate_id(d.get("kid"), "kid", 256),
            sig=sig,
            v=v,
        )

    @classmethod
    def from_json(cls, s: str) -> CollectionManifest:
        if len(s.encode("utf-8", errors="surrogatepass")) > _MAX_MANIFEST_JSON_BYTES:
            raise ValueError("manifest JSON too large")
        return cls.from_dict(json.loads(s))


def build_manifest(
    signer: Signer,
    collection_id: str,
    entries: Iterable[tuple[str, str]],
    *,
    timestamp: datetime | None = None,
) -> CollectionManifest:
    """Build and sign a manifest over ``(record_id, vec_hash)`` entries.

    Call this from the ingestion pipeline once a batch has been written
    and pinned, with every record in the collection. Store the result
    somewhere the database administrator cannot rewrite.
    """
    items = list(entries)
    root = merkle_root(items)
    ts = (
        timestamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        if timestamp is not None
        else _now_ts()
    )
    unsigned = CollectionManifest(
        collection_id=_validate_id(collection_id, "collection_id", _MAX_COLLECTION_ID_BYTES),
        count=len(items),
        merkle_root=root,
        ts=_validate_ts(ts, "ts"),
        kid=signer.key_id,
        sig=b"",
    )
    sig = signer._sign_with_domain(MANIFEST_DOMAIN_TAG, unsigned.canonical_payload())
    return CollectionManifest(
        collection_id=unsigned.collection_id,
        count=unsigned.count,
        merkle_root=unsigned.merkle_root,
        ts=unsigned.ts,
        kid=unsigned.kid,
        sig=sig,
    )


def verify_manifest(
    manifest: CollectionManifest,
    verifier: Verifier,
    entries: Iterable[tuple[str, str]],
    *,
    expected_collection_id: str | None = None,
) -> ManifestResult:
    """Check a manifest's signature and compare it to the store's state.

    ``entries`` are the ``(record_id, vec_hash)`` pairs the audit just
    observed (empty-string hash for unpinned or unparseable records).
    Never raises on manifest content.
    """
    from cryptography.exceptions import InvalidSignature

    try:
        public_key = verifier.public_key_for(manifest.kid)
        if public_key is None:
            return ManifestResult(
                False, ManifestError.UNKNOWN_KEY, f"no registered key for kid={manifest.kid!r}"
            )
        try:
            public_key.verify(manifest.sig, MANIFEST_DOMAIN_TAG + manifest.canonical_payload())
        except InvalidSignature:
            return ManifestResult(
                False, ManifestError.SIGNATURE_INVALID, "manifest signature did not verify"
            )
        if expected_collection_id is not None and manifest.collection_id != expected_collection_id:
            return ManifestResult(
                False,
                ManifestError.COLLECTION_MISMATCH,
                f"manifest collection_id {manifest.collection_id!r} != expected "
                f"{expected_collection_id!r}",
            )
        items = list(entries)
        if len(items) != manifest.count:
            return ManifestResult(
                False,
                ManifestError.COUNT_MISMATCH,
                f"store holds {len(items)} records; manifest commits to {manifest.count}",
            )
        observed = merkle_root(items)
        if observed != manifest.merkle_root:
            return ManifestResult(
                False,
                ManifestError.ROOT_MISMATCH,
                "record set differs from the manifest (records added, removed, "
                "re-pinned, or pins stripped)",
            )
        return ManifestResult(True, ManifestError.OK)
    except Exception as e:  # never-raise contract
        return ManifestResult(
            False, ManifestError.PARSE_ERROR, f"manifest verification aborted: {e}"
        )


# ---- signed audit summaries -------------------------------------------------

_SUMMARY_SIG_FIELDS = ("summary_kid", "summary_ts", "summary_sig")


def sign_audit_summary(summary: dict[str, Any], signer: Signer) -> dict[str, Any]:
    """Return a copy of ``summary`` carrying an Ed25519 signature.

    Adds ``summary_kid``, ``summary_ts`` and ``summary_sig``; the
    signature covers every other key, so a forged or edited report
    fails :func:`verify_audit_summary`.
    """
    body = {k: v for k, v in summary.items() if k not in _SUMMARY_SIG_FIELDS}
    body["summary_kid"] = signer.key_id
    body["summary_ts"] = _now_ts()
    sig = signer._sign_with_domain(AUDIT_SUMMARY_DOMAIN_TAG, _canonical_json(body))
    body["summary_sig"] = _b64(sig)
    return body


def verify_audit_summary(summary: dict[str, Any], verifier: Verifier) -> ManifestResult:
    """Verify a summary produced by :func:`sign_audit_summary`. Never raises."""
    from cryptography.exceptions import InvalidSignature

    try:
        if not isinstance(summary, dict):
            return ManifestResult(False, ManifestError.PARSE_ERROR, "summary must be an object")
        kid = summary.get("summary_kid")
        sig_raw = summary.get("summary_sig")
        if not isinstance(kid, str) or not isinstance(sig_raw, str):
            return ManifestResult(
                False, ManifestError.PARSE_ERROR, "summary is missing signature fields"
            )
        _validate_ts(summary.get("summary_ts"), "summary_ts")
        sig = _b64dec(sig_raw)
        if len(sig) != 64:
            return ManifestResult(False, ManifestError.PARSE_ERROR, "summary_sig is not 64 bytes")
        public_key = verifier.public_key_for(kid)
        if public_key is None:
            return ManifestResult(
                False, ManifestError.UNKNOWN_KEY, f"no registered key for kid={kid!r}"
            )
        body = {k: v for k, v in summary.items() if k != "summary_sig"}
        try:
            public_key.verify(sig, AUDIT_SUMMARY_DOMAIN_TAG + _canonical_json(body))
        except InvalidSignature:
            return ManifestResult(
                False, ManifestError.SIGNATURE_INVALID, "summary signature did not verify"
            )
        return ManifestResult(True, ManifestError.OK)
    except Exception as e:  # never-raise contract
        return ManifestResult(False, ManifestError.PARSE_ERROR, f"summary unparseable: {e}")
