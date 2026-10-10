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

Contract: ``Verifier.verify`` never raises on account of pin content or
the supplied ground truth. Any exception escaping the checks is mapped
to ``PARSE_ERROR`` so a hostile or corrupt record cannot turn a read
path into an exception path. Only verifier *configuration* errors (for
example a naive datetime in a ``KeyEntry``) raise, and they raise at
construction time, never from ``verify``.
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
from vectorpin.hash import hash_text, hash_vector, is_wider_than, native_dtype


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


def _require_aware(value: datetime | None, field_name: str) -> None:
    """Reject naive datetimes in verifier configuration.

    Pin timestamps parse to timezone-aware UTC datetimes; comparing them
    against a naive datetime raises ``TypeError`` deep inside
    ``verify()``. Catching that at construction keeps the read path
    exception-free and makes the misconfiguration obvious.
    """
    if value is None:
        return
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime or None")
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(
            f"{field_name} must be timezone-aware (use tzinfo=timezone.utc)"
        )


@dataclass(frozen=True)
class KeyEntry:
    """A registered public key, with an optional validity window (§7).

    `valid_from` / `valid_until` are inclusive of `valid_from` and
    exclusive of `valid_until` per common convention. If both are None,
    the key validates pins of any `ts`.

    Both bounds MUST be timezone-aware datetimes; naive values are
    rejected at construction.
    """

    public_key: Ed25519PublicKey
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    def __post_init__(self) -> None:
        _require_aware(self.valid_from, "valid_from")
        _require_aware(self.valid_until, "valid_until")


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

    def public_key_for(self, kid: str) -> Ed25519PublicKey | None:
        """Registered public key for ``kid``, or ``None`` if unknown.

        Used by sibling message types (collection manifests, signed
        audit summaries) that share the pin key registry.
        """
        entry = self._keys.get(kid)
        return entry.public_key if entry is not None else None

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
        expected_model_hash: str | None = None,
        expected_record_id: str | None = None,
        expected_collection_id: str | None = None,
        expected_tenant_id: str | None = None,
        trusted_time: datetime | None = None,
    ) -> VerificationResult:
        """Verify a Pin against optional ground-truth source/vector.

        The signature check always runs. The other checks run only when
        the corresponding ground truth is supplied — letting callers do
        partial verification (e.g. signature-only when the source text
        is unavailable but the producer identity still matters).

        ``vector`` MUST be a floating-point array whose element width is
        no wider than the pin's ``vec_dtype``. A wider array (for
        example ``float64`` against an ``f32`` pin) is rejected as
        ``SHAPE_MISMATCH`` rather than cast: casting before hashing would
        leave every low-order bit the cast discards unverified (§3.2).

        ``expected_model_hash`` compares against the pin's optional
        ``model_hash``; a pin without one fails ``MODEL_MISMATCH``.

        Replay-protection identifiers (§5 step 8): if any of
        ``expected_record_id``, ``expected_collection_id``, or
        ``expected_tenant_id`` is supplied, the verifier compares it
        against the value at ``vectorpin.record_id`` /
        ``vectorpin.collection_id`` / ``vectorpin.tenant_id`` in the
        pin's ``extra`` map. A missing or mismatched value rejects.

        ``trusted_time`` is a timezone-aware instant from a clock the
        signing-key holder cannot write (for example the store's own
        ingestion timestamp). When supplied, the key validity window is
        evaluated against it instead of the signer-chosen ``ts``, and a
        pin whose ``ts`` postdates it is rejected. Without it, the
        window only bounds honest signers (§7).

        This method never raises on account of pin content; unexpected
        exceptions are reported as ``PARSE_ERROR``.
        """
        try:
            return self._verify_inner(
                pin,
                source=source,
                vector=vector,
                expected_model=expected_model,
                expected_model_hash=expected_model_hash,
                expected_record_id=expected_record_id,
                expected_collection_id=expected_collection_id,
                expected_tenant_id=expected_tenant_id,
                trusted_time=trusted_time,
            )
        except Exception as e:  # never-raise contract
            return VerificationResult(
                False,
                VerifyError.PARSE_ERROR,
                f"verification aborted on malformed input: {type(e).__name__}: {e}",
            )

    def _verify_inner(
        self,
        pin: Pin,
        *,
        source: str | None,
        vector: np.ndarray | None,
        expected_model: str | None,
        expected_model_hash: str | None,
        expected_record_id: str | None,
        expected_collection_id: str | None,
        expected_tenant_id: str | None,
        trusted_time: datetime | None,
    ) -> VerificationResult:
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

        if trusted_time is not None:
            _require_aware(trusted_time, "trusted_time")

        if (
            entry.valid_from is not None
            or entry.valid_until is not None
            or trusted_time is not None
        ):
            pin_ts = _parse_ts(pin.header.ts)
            if pin_ts is None:
                return VerificationResult(
                    False,
                    VerifyError.KEY_EXPIRED,
                    "pin ts unparseable; cannot evaluate key validity window",
                )
            # The instant the window is evaluated at. `ts` is chosen by
            # whoever holds the signing key, so on its own it only bounds
            # honest signers; a caller-supplied trusted time binds the
            # window to a clock the key holder cannot write.
            window_ts = pin_ts
            if trusted_time is not None:
                if pin_ts > trusted_time:
                    return VerificationResult(
                        False,
                        VerifyError.KEY_EXPIRED,
                        f"pin ts {pin.header.ts} postdates the trusted time "
                        f"{trusted_time.isoformat()}",
                    )
                window_ts = trusted_time
            if entry.valid_from is not None and window_ts < entry.valid_from:
                return VerificationResult(
                    False,
                    VerifyError.KEY_EXPIRED,
                    f"pin ts {pin.header.ts} predates key valid_from",
                )
            if entry.valid_until is not None and window_ts >= entry.valid_until:
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

        # Step 5: source check.
        if source is not None:
            try:
                source_hash = hash_text(source)
            except ValueError as e:
                return VerificationResult(
                    False,
                    VerifyError.PARSE_ERROR,
                    f"supplied source cannot be hashed: {e}",
                )
            if source_hash != pin.header.source_hash:
                return VerificationResult(
                    False,
                    VerifyError.SOURCE_MISMATCH,
                    "source hash mismatch — pinned source differs from supplied source",
                )

        # Step 6: vector check. Vector NaN/Inf at verify time is a
        # parse error per §5 step 6 — reject before hashing.
        if vector is not None:
            if not isinstance(vector, np.ndarray):
                return VerificationResult(
                    False,
                    VerifyError.SHAPE_MISMATCH,
                    f"vector must be a numpy array; got {type(vector).__name__}",
                )
            if vector.ndim != 1 or vector.shape[0] != pin.header.vec_dim:
                return VerificationResult(
                    False,
                    VerifyError.SHAPE_MISMATCH,
                    f"vector shape {vector.shape} does not match pin (dim={pin.header.vec_dim})",
                )
            # Precision check (§3.2): the supplied array must not hold
            # more bits than the pinned dtype. Casting first would make
            # every value that rounds to the same pinned value verify
            # identically, leaving the discarded bits as a covert channel.
            if is_wider_than(vector, pin.header.vec_dtype):
                return VerificationResult(
                    False,
                    VerifyError.SHAPE_MISMATCH,
                    f"supplied vector dtype {vector.dtype} is wider than pinned "
                    f"vec_dtype {pin.header.vec_dtype!r}; low-order bits would be "
                    "unverified. Pin under the dtype your store persists.",
                )
            if not np.isfinite(vector).all():
                return VerificationResult(
                    False,
                    VerifyError.PARSE_ERROR,
                    "supplied vector contains NaN or infinity",
                )
            if hash_vector(vector, pin.header.vec_dtype) != pin.header.vec_hash:
                detail = "vector hash mismatch — embedding has been modified after pinning"
                supplied = native_dtype(vector)
                if supplied != pin.header.vec_dtype:
                    detail += (
                        f" (supplied vector is {supplied} but the pin was signed as "
                        f"{pin.header.vec_dtype}; if your store persists {supplied}, "
                        f"pin with vec_dtype={supplied!r})"
                    )
                return VerificationResult(False, VerifyError.VECTOR_TAMPERED, detail)

        # Step 7: model check.
        if expected_model is not None and pin.header.model != expected_model:
            return VerificationResult(
                False,
                VerifyError.MODEL_MISMATCH,
                f"pin model {pin.header.model!r} != expected {expected_model!r}",
            )
        if expected_model_hash is not None and pin.header.model_hash != expected_model_hash:
            return VerificationResult(
                False,
                VerifyError.MODEL_MISMATCH,
                f"pin model_hash {pin.header.model_hash!r} != expected "
                f"{expected_model_hash!r}",
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
