# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin signing.

We use Ed25519 because:
  - Signatures are 64 bytes (compact in DB metadata).
  - Public keys are 32 bytes.
  - Deterministic — same input always produces the same signature.
  - Widely supported across languages (matters for Symbiont's Rust runtime
    and any future MCP server implementations).

A Signer wraps a single (private_key, key_id) pair. Key rotation is a
deployment concern: issue a new (key_id, key) and have the verifier
accept multiple kids during the rotation window.
"""

from __future__ import annotations

from datetime import UTC, datetime

import numpy as np
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vectorpin.attestation import PROTOCOL_VERSION, Pin, PinHeader
from vectorpin.hash import CanonicalDtype, hash_text, hash_vector


class Signer:
    """Produces Pin attestations for embeddings.

    A Signer holds one ed25519 private key. The corresponding public key
    is published with `key_id` so verifiers can route signatures to the
    right key during rotation.
    """

    def __init__(self, private_key: Ed25519PrivateKey, key_id: str):
        if not key_id:
            raise ValueError("key_id must be non-empty")
        self._private_key = private_key
        self._key_id = key_id

    @classmethod
    def generate(cls, key_id: str) -> Signer:
        """Generate a fresh ed25519 signer. Tests and demos only.

        Production deployments should load private keys from a managed
        secrets store, not generate them per-process.
        """
        return cls(Ed25519PrivateKey.generate(), key_id)

    @classmethod
    def from_private_bytes(cls, raw: bytes, key_id: str) -> Signer:
        """Load a signer from a 32-byte ed25519 private seed."""
        return cls(Ed25519PrivateKey.from_private_bytes(raw), key_id)

    @classmethod
    def from_pem(
        cls,
        pem: bytes,
        key_id: str,
        password: bytes | None = None,
        *,
        allow_unencrypted: bool = False,
    ) -> Signer:
        """Load a signer from PEM-encoded PKCS#8 ed25519 key material.

        Callers must either provide a `password` to decrypt an
        encrypted PEM, or set `allow_unencrypted=True` to opt in to
        loading an unencrypted file. The default is to refuse:
        unencrypted private keys on disk are a footgun, and we want a
        positive confirmation that the caller knew the file lacked
        encryption.
        """
        if password is None and not allow_unencrypted:
            raise ValueError(
                "PEM is unencrypted; pass allow_unencrypted=True to confirm"
            )
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError(f"expected Ed25519PrivateKey, got {type(key).__name__}")
        return cls(key, key_id)

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def public_key_bytes(self) -> bytes:
        """32-byte raw ed25519 public key — what verifiers actually need."""
        return self.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def private_key_bytes(self) -> bytes:
        """32-byte raw ed25519 private seed. Treat as a secret."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def pin(
        self,
        source: str,
        model: str,
        vector: np.ndarray,
        *,
        vec_dtype: CanonicalDtype = "f32",
        model_hash: str | None = None,
        timestamp: datetime | None = None,
        extra: dict[str, str] | None = None,
    ) -> Pin:
        """Create a Pin for (source, model, vector).

        Args:
            source: The exact source text the embedding was produced from.
                Hashed and committed to; the verifier needs the same text
                to validate the pin.
            model: Embedding model identifier, e.g. 'text-embedding-3-large'.
                Treat as opaque — the verifier just compares strings.
            vector: 1-D numpy array, the embedding itself.
            vec_dtype: Canonical dtype to hash under. Default 'f32'.
            model_hash: Optional content hash of the model weights, if
                pinning to a specific local model file.
            timestamp: Optional explicit timestamp. Default: now (UTC).
            extra: Optional string-to-string metadata committed under the
                signature. Use sparingly — every key adds attack surface.

        Returns:
            A signed Pin. Serialize with `pin.to_json()` and store
            alongside the vector in the DB metadata.
        """
        if timestamp is None:
            timestamp = datetime.now(UTC)
        ts_iso = timestamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        header = PinHeader(
            v=PROTOCOL_VERSION,
            model=model,
            model_hash=model_hash,
            source_hash=hash_text(source),
            vec_hash=hash_vector(vector, vec_dtype),
            vec_dtype=vec_dtype,
            vec_dim=int(vector.shape[0]),
            ts=ts_iso,
            extra=dict(extra) if extra else {},
        )
        sig = self._private_key.sign(header.canonicalize())
        return Pin(header=header, kid=self._key_id, sig=sig)
