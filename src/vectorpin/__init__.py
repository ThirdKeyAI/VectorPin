# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""VectorPin — verifiable integrity for AI embedding stores.

VectorPin pins each embedding to its source content and the model that
produced it, then continuously verifies the store has not been tampered
with — including covert steganographic modifications invisible to
traditional DLP.

Part of the ThirdKey Trust Stack.

Quick start:

    from vectorpin import Signer, Verifier, Pin

    signer = Signer.generate(key_id="prod-2026-05")
    pin = signer.pin(
        source="The quick brown fox.",
        model="text-embedding-3-large",
        vector=embedding_vector,
    )
    # Store pin alongside the vector in your DB metadata.

    verifier = Verifier(public_keys={"prod-2026-05": signer.public_key()})
    assert verifier.verify(pin, source="The quick brown fox.", vector=embedding_vector)
"""

from vectorpin.attestation import (
    DOMAIN_TAG,
    PROTOCOL_VERSION,
    Pin,
    PinHeader,
)
from vectorpin.hash import canonical_vector_bytes, hash_text, hash_vector
from vectorpin.signer import Signer
from vectorpin.verifier import (
    KeyEntry,
    LegacyV1Verifier,
    VerificationResult,
    Verifier,
    VerifyError,
)

__version__ = "0.2.0"
__all__ = [
    "DOMAIN_TAG",
    "PROTOCOL_VERSION",
    "KeyEntry",
    "LegacyV1Verifier",
    "Pin",
    "PinHeader",
    "Signer",
    "VerificationResult",
    "Verifier",
    "VerifyError",
    "canonical_vector_bytes",
    "hash_text",
    "hash_vector",
]
