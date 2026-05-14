# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin verification.

Three failure modes, in order of severity:

  1. SignatureInvalid — the producer is not who the pin claims, or the
     attestation has been re-signed by an attacker.
  2. VectorTampered — the vector in the store does not match what the
     producer attested to. This is the steganography kill shot.
  3. SourceMismatch — the source text the verifier is checking against
     does not match what the producer pinned. Either the verifier has
     the wrong text, or the source corpus drifted.

The Verifier returns a structured VerificationResult so callers can
distinguish these and route them differently (alert vs. quarantine vs.
re-pin).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vectorpin.attestation import PROTOCOL_VERSION, Pin
from vectorpin.hash import hash_text, hash_vector


class VerifyError(Enum):
    """Distinct failure modes that callers can route on."""

    OK = "ok"
    UNKNOWN_KEY = "unknown_key"
    UNSUPPORTED_VERSION = "unsupported_version"
    SIGNATURE_INVALID = "signature_invalid"
    VECTOR_TAMPERED = "vector_tampered"
    SOURCE_MISMATCH = "source_mismatch"
    MODEL_MISMATCH = "model_mismatch"
    SHAPE_MISMATCH = "shape_mismatch"


@dataclass(frozen=True)
class VerificationResult:
    """Structured result. Truthy iff verification succeeded."""

    ok: bool
    error: VerifyError
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ok


def _public_key_from_bytes(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


class Verifier:
    """Verifies Pin attestations against a key registry.

    The registry maps key id -> public key. Verifiers MUST be willing to
    hold multiple keys at once to support rotation: when a new signing
    key is introduced, both the old and new public keys live in the
    registry until the rotation window closes.
    """

    def __init__(self, public_keys: dict[str, Ed25519PublicKey | bytes]):
        self._keys: dict[str, Ed25519PublicKey] = {}
        for kid, key in public_keys.items():
            if isinstance(key, bytes):
                self._keys[kid] = _public_key_from_bytes(key)
            elif isinstance(key, Ed25519PublicKey):
                self._keys[kid] = key
            else:
                raise TypeError(f"public key for {kid!r} must be Ed25519PublicKey or bytes")

    def add_key(self, kid: str, key: Ed25519PublicKey | bytes) -> None:
        """Register an additional public key — used during rotation."""
        if isinstance(key, bytes):
            key = _public_key_from_bytes(key)
        self._keys[kid] = key

    def verify(
        self,
        pin: Pin,
        *,
        source: str | None = None,
        vector: np.ndarray | None = None,
        expected_model: str | None = None,
    ) -> VerificationResult:
        """Verify a Pin against optional ground-truth source/vector.

        The signature check always runs. The other checks run only when
        the corresponding ground truth is supplied — letting callers do
        partial verification (e.g. signature-only when the source text
        is unavailable but the producer identity still matters).
        """
        if pin.header.v != PROTOCOL_VERSION:
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

        public_key = self._keys.get(pin.kid)
        if public_key is None:
            return VerificationResult(
                False,
                VerifyError.UNKNOWN_KEY,
                f"no registered public key for kid={pin.kid!r}",
            )

        try:
            public_key.verify(pin.sig, pin.header.canonicalize())
        except InvalidSignature:
            return VerificationResult(
                False,
                VerifyError.SIGNATURE_INVALID,
                "ed25519 signature did not verify",
            )

        if vector is not None:
            if vector.ndim != 1 or vector.shape[0] != pin.header.vec_dim:
                return VerificationResult(
                    False,
                    VerifyError.SHAPE_MISMATCH,
                    f"vector shape {vector.shape} does not match pin (dim={pin.header.vec_dim})",
                )
            if hash_vector(vector, pin.header.vec_dtype) != pin.header.vec_hash:
                return VerificationResult(
                    False,
                    VerifyError.VECTOR_TAMPERED,
                    "vector hash mismatch — embedding has been modified after pinning",
                )

        if source is not None and hash_text(source) != pin.header.source_hash:
            return VerificationResult(
                False,
                VerifyError.SOURCE_MISMATCH,
                "source hash mismatch — pinned source differs from supplied source",
            )

        if expected_model is not None and pin.header.model != expected_model:
            return VerificationResult(
                False,
                VerifyError.MODEL_MISMATCH,
                f"pin model {pin.header.model!r} != expected {expected_model!r}",
            )

        return VerificationResult(True, VerifyError.OK)
