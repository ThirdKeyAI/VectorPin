# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin verification.

Failure modes, in rough order of severity:

  1. PARSE_ERROR     — pin JSON failed wire-format validation before any
                       cryptographic work was attempted.
  2. UNSUPPORTED_VERSION / UNKNOWN_KEY / KEY_EXPIRED — registry-level
                       problems; signature was never checked.
  3. SIGNATURE_INVALID — the producer is not who the pin claims, or the
                       attestation has been re-signed by an attacker.
  4. VECTOR_TAMPERED — the vector in the store does not match what the
                       producer attested to. The steganography kill shot.
  5. SOURCE_MISMATCH — the source text the verifier is checking against
                       does not match what the producer pinned.
  6. MODEL_MISMATCH / SHAPE_MISMATCH — provided ground truth does not
                       match what the pin attested to.
  7. RECORD_MISMATCH / COLLECTION_MISMATCH / TENANT_MISMATCH — caller
                       supplied an expected replay-protection identifier
                       that did not match the pin's `extra` value (§5.8).

The Verifier returns a structured VerificationResult so callers can
distinguish these and route them differently (alert vs. quarantine vs.
re-pin).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vectorpin.attestation import (
    PROTOCOL_VERSION,
    Pin,
    _canonicalize_v1,
)
from vectorpin.hash import hash_text, hash_vector


class VerifyError(Enum):
    """Distinct failure modes that callers can route on."""

    OK = "ok"
    UNKNOWN_KEY = "unknown_key"
    UNSUPPORTED_VERSION = "unsupported_version"
    KEY_EXPIRED = "key_expired"
    PARSE_ERROR = "parse_error"
    SIGNATURE_INVALID = "signature_invalid"
    VECTOR_TAMPERED = "vector_tampered"
    SOURCE_MISMATCH = "source_mismatch"
    MODEL_MISMATCH = "model_mismatch"
    SHAPE_MISMATCH = "shape_mismatch"
    RECORD_MISMATCH = "record_mismatch"
    COLLECTION_MISMATCH = "collection_mismatch"
    TENANT_MISMATCH = "tenant_mismatch"


@dataclass(frozen=True)
class VerificationResult:
    """Structured result. Truthy iff verification succeeded."""

    ok: bool
    error: VerifyError
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ok


@dataclass(frozen=True)
class KeyEntry:
    """A registered public key, with an optional validity window (§7).

    `valid_from` / `valid_until` are inclusive of `valid_from` and
    exclusive of `valid_until` per common convention. If both are None,
    the key validates pins of any `ts`.
    """

    public_key: Ed25519PublicKey
    valid_from: datetime | None = None
    valid_until: datetime | None = None


def _public_key_from_bytes(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def _coerce_entry(
    key: Ed25519PublicKey | bytes | KeyEntry, kid: str
) -> KeyEntry:
    if isinstance(key, KeyEntry):
        return key
    if isinstance(key, bytes):
        return KeyEntry(public_key=_public_key_from_bytes(key))
    if isinstance(key, Ed25519PublicKey):
        return KeyEntry(public_key=key)
    raise TypeError(
        f"public key for {kid!r} must be Ed25519PublicKey, bytes, or KeyEntry"
    )


def _parse_ts(ts: str) -> datetime | None:
    """Parse a pin's `ts` to UTC datetime. Returns None on failure.

    Used only for validity-window checks; a malformed ts here means
    the registry can't decide whether the key was valid at pin time,
    so we conservatively reject as KEY_EXPIRED rather than allowing.
    """
    try:
        # v2 ts is YYYY-MM-DDTHH:MM:SSZ; fromisoformat needs +00:00 or
        # a stripped Z. Strip the trailing Z to keep semantics
        # consistent across Python versions.
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


@dataclass
class _ReplayCheck:
    """Bundle of optional replay-protection identifiers the caller
    can supply to verify(). Each maps to a reserved `extra` key (§8).
    """

    record_id: str | None = None
    collection_id: str | None = None
    tenant_id: str | None = None


class Verifier:
    """Verifies Pin attestations against a key registry.

    The registry maps key id -> public key. Verifiers MUST be willing to
    hold multiple keys at once to support rotation: when a new signing
    key is introduced, both the old and new public keys live in the
    registry until the rotation window closes.

    The default verifier accepts only protocol v2 pins. To accept
    legacy v1 pins for migration purposes, use ``LegacyV1Verifier`` or
    pass ``accept_v1_legacy=True`` here. Legacy mode is opt-in
    because v1 pins lack the §12 audit fixes.
    """

    _accepted_versions: frozenset[int] = frozenset({PROTOCOL_VERSION})

    def __init__(
        self,
        public_keys: dict[str, Ed25519PublicKey | bytes | KeyEntry],
        *,
        accept_v1_legacy: bool = False,
    ):
        self._keys: dict[str, KeyEntry] = {
            kid: _coerce_entry(key, kid) for kid, key in public_keys.items()
        }
        self._accept_v1_legacy = accept_v1_legacy

    def add_key(
        self,
        kid: str,
        key: Ed25519PublicKey | bytes | KeyEntry,
        *,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
    ) -> None:
        """Register an additional public key — used during rotation."""
        entry = _coerce_entry(key, kid)
        if valid_from is not None or valid_until is not None:
            entry = KeyEntry(
                public_key=entry.public_key,
                valid_from=valid_from if valid_from is not None else entry.valid_from,
                valid_until=valid_until if valid_until is not None else entry.valid_until,
            )
        self._keys[kid] = entry

    def _canonical_for(self, pin: Pin) -> bytes:
        """Reconstruct the canonical bytes a signer would have signed.

        Dispatches on the pin's `v` field so the legacy verifier can
        share most of this code path. v2 emits `DOMAIN_TAG || json`;
        v1 emits just the (kid-less) json.
        """
        if pin.header.v == 1:
            return _canonicalize_v1(pin.header)
        return pin.header.canonicalize()

    def verify(
        self,
        pin: Pin,
        *,
        source: str | None = None,
        vector: np.ndarray | None = None,
        expected_model: str | None = None,
        expected_record_id: str | None = None,
        expected_collection_id: str | None = None,
        expected_tenant_id: str | None = None,
    ) -> VerificationResult:
        """Verify a Pin against optional ground-truth source/vector.

        The signature check always runs. The other checks run only when
        the corresponding ground truth is supplied — letting callers do
        partial verification (e.g. signature-only when the source text
        is unavailable but the producer identity still matters).

        Replay-protection identifiers (§5 step 8): if any of
        ``expected_record_id``, ``expected_collection_id``, or
        ``expected_tenant_id`` is supplied, the verifier compares it
        against the value at ``vectorpin.record_id`` /
        ``vectorpin.collection_id`` / ``vectorpin.tenant_id`` in the
        pin's ``extra`` map. A missing or mismatched value rejects.
        """
        # Step 1: version dispatch.
        accepted = self._accepted_versions
        if self._accept_v1_legacy:
            accepted = accepted | {1}
        if pin.header.v not in accepted:
            return VerificationResult(
                False,
                VerifyError.UNSUPPORTED_VERSION,
                f"pin version {pin.header.v} not supported by this verifier",
            )

        # Pre-check signature shape before any cryptographic work so a
        # malformed pin produces a structured SIGNATURE_INVALID rather
        # than letting a downstream exception escape.
        if not isinstance(pin.sig, (bytes, bytearray)) or len(pin.sig) != 64:
            if isinstance(pin.sig, (bytes, bytearray)):
                detail = f"signature must be exactly 64 bytes; got {len(pin.sig)}"
            else:
                detail = (
                    f"signature must be exactly 64 bytes; "
                    f"got {type(pin.sig).__name__}"
                )
            return VerificationResult(False, VerifyError.SIGNATURE_INVALID, detail)

        # Step 2: kid lookup + validity window.
        entry = self._keys.get(pin.kid)
        if entry is None:
            return VerificationResult(
                False,
                VerifyError.UNKNOWN_KEY,
                f"no registered public key for kid={pin.kid!r}",
            )

        if entry.valid_from is not None or entry.valid_until is not None:
            pin_ts = _parse_ts(pin.header.ts)
            if pin_ts is None:
                return VerificationResult(
                    False,
                    VerifyError.KEY_EXPIRED,
                    "pin ts unparseable; cannot evaluate key validity window",
                )
            if entry.valid_from is not None and pin_ts < entry.valid_from:
                return VerificationResult(
                    False,
                    VerifyError.KEY_EXPIRED,
                    f"pin ts {pin.header.ts} predates key valid_from",
                )
            if entry.valid_until is not None and pin_ts >= entry.valid_until:
                return VerificationResult(
                    False,
                    VerifyError.KEY_EXPIRED,
                    f"pin ts {pin.header.ts} is at or past key valid_until",
                )

        # Step 4: signature.
        try:
            entry.public_key.verify(pin.sig, self._canonical_for(pin))
        except InvalidSignature:
            return VerificationResult(
                False,
                VerifyError.SIGNATURE_INVALID,
                "ed25519 signature did not verify",
            )

        # Step 6: vector check. Vector NaN/Inf at verify time is a
        # parse error per §5 step 6 — reject before hashing.
        if vector is not None:
            if vector.ndim != 1 or vector.shape[0] != pin.header.vec_dim:
                return VerificationResult(
                    False,
                    VerifyError.SHAPE_MISMATCH,
                    f"vector shape {vector.shape} does not match pin (dim={pin.header.vec_dim})",
                )
            if not np.isfinite(vector).all():
                return VerificationResult(
                    False,
                    VerifyError.PARSE_ERROR,
                    "supplied vector contains NaN or infinity",
                )
            if hash_vector(vector, pin.header.vec_dtype) != pin.header.vec_hash:
                return VerificationResult(
                    False,
                    VerifyError.VECTOR_TAMPERED,
                    "vector hash mismatch — embedding has been modified after pinning",
                )

        # Step 5: source check.
        if source is not None and hash_text(source) != pin.header.source_hash:
            return VerificationResult(
                False,
                VerifyError.SOURCE_MISMATCH,
                "source hash mismatch — pinned source differs from supplied source",
            )

        # Step 7: model check.
        if expected_model is not None and pin.header.model != expected_model:
            return VerificationResult(
                False,
                VerifyError.MODEL_MISMATCH,
                f"pin model {pin.header.model!r} != expected {expected_model!r}",
            )

        # Step 8: replay-protection identifier checks. Reserved
        # `vectorpin.*` keys are tamper-evident because every `extra`
        # entry is signed.
        replay = (
            ("vectorpin.record_id", expected_record_id, VerifyError.RECORD_MISMATCH),
            (
                "vectorpin.collection_id",
                expected_collection_id,
                VerifyError.COLLECTION_MISMATCH,
            ),
            (
                "vectorpin.tenant_id",
                expected_tenant_id,
                VerifyError.TENANT_MISMATCH,
            ),
        )
        for key, expected, err in replay:
            if expected is None:
                continue
            actual = pin.header.extra.get(key)
            if actual != expected:
                return VerificationResult(
                    False,
                    err,
                    f"pin extra[{key!r}]={actual!r} != expected {expected!r}",
                )

        return VerificationResult(True, VerifyError.OK)


class LegacyV1Verifier(Verifier):
    """Verifier that accepts protocol v1 pins for migration purposes.

    This dispatches v1 pins to the v1 canonicalization (no domain tag,
    no kid in the signed bytes) so historical pins continue to verify
    byte-for-byte against their original signatures. v2 pins are still
    accepted by this verifier so a migration window can verify both
    formats from the same registry.

    Per spec §5 step 1: legacy mode MUST be opt-in and SHOULD be
    disabled by default. Use this class explicitly, do not enable it
    in shared infrastructure paths.

    To parse a v1 pin JSON string under this verifier, call
    ``LegacyV1Verifier.parse_pin(s)`` — the default ``Pin.from_json``
    rejects v1 pins because the strict v2 wire-format rules don't
    apply to them.
    """

    _accepted_versions = frozenset({1, PROTOCOL_VERSION})
    _ACCEPT_PARSE_VERSIONS = frozenset({1, PROTOCOL_VERSION})

    def __init__(
        self, public_keys: dict[str, Ed25519PublicKey | bytes | KeyEntry]
    ):
        super().__init__(public_keys, accept_v1_legacy=True)

    @classmethod
    def parse_pin(cls, s: str | dict) -> Pin:
        """Parse a v1 or v2 pin JSON string / dict.

        v1 pins are subject to the v1 parser's looser rules (no NFC
        enforcement, no strict ts regex), so historical artifacts
        load. v2 pins still go through the strict v2 parser.
        """
        if isinstance(s, dict):
            return Pin.from_dict(s, accept_versions=cls._ACCEPT_PARSE_VERSIONS)
        return Pin.from_json(s, accept_versions=cls._ACCEPT_PARSE_VERSIONS)
