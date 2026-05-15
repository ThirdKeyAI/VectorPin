#!/usr/bin/env python
# Copyright 2025-2026 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""End-to-end verification of PineconeAdapter against Pinecone Cloud.

This is a manual integration check, not a CI test. It creates a fresh
serverless index, seeds one record, runs the full
attach-pin / re-fetch / verify roundtrip via :class:`PineconeAdapter`,
exercises a tamper-rejection path, and deletes the index on exit
(success *or* failure, via ``try / finally``).

Use it when:

  - You want to confirm the adapter still works against the live
    Pinecone API after a client-library upgrade.
  - You want a no-fixtures-required smoke test against a real account.
  - You want a worked example of the create-seed-verify-cleanup
    pattern for opt-in cloud integration scripts.

Usage
-----

::

    export PINECONE_API_KEY=pcsk_xxx
    python scripts/pinecone_live_e2e.py

Optional env vars (all have safe defaults):

    PINECONE_INDEX_NAME    name to create (default: vectorpin-e2e-<uuid>)
    PINECONE_NAMESPACE     namespace for the seed record (default: vectorpin-test)
    PINECONE_CLOUD         serverless cloud (default: aws)
    PINECONE_REGION        serverless region (default: us-east-1)
    PINECONE_READY_TIMEOUT seconds to wait for index ready (default: 120)

Cost note
---------

On Pinecone Serverless the cost of one create + one upsert + a handful
of fetches against a 16-dim record is well under one cent. The index is
deleted on exit; nothing persists in the account after the script
returns.
"""

from __future__ import annotations

import os
import sys
import time
import uuid

import numpy as np
from pinecone import Pinecone, ServerlessSpec

from vectorpin import Signer, Verifier
from vectorpin.adapters import PineconeAdapter


def main() -> int:
    api_key = os.environ.get("PINECONE_API_KEY")
    if not api_key:
        print("PINECONE_API_KEY not set", file=sys.stderr)
        return 2

    index_name = os.environ.get(
        "PINECONE_INDEX_NAME", f"vectorpin-e2e-{uuid.uuid4().hex[:10]}"
    )
    namespace = os.environ.get("PINECONE_NAMESPACE", "vectorpin-test")
    cloud = os.environ.get("PINECONE_CLOUD", "aws")
    region = os.environ.get("PINECONE_REGION", "us-east-1")
    ready_timeout = int(os.environ.get("PINECONE_READY_TIMEOUT", "120"))

    dim = 16
    record_id = "test-record-1"

    pc = Pinecone(api_key=api_key)

    print(
        f"[1/6] creating serverless index {index_name!r} "
        f"({dim}-dim, cosine, {cloud} {region})"
    )
    pc.create_index(
        name=index_name,
        dimension=dim,
        metric="cosine",
        spec=ServerlessSpec(cloud=cloud, region=region),
    )

    try:
        print(f"[2/6] waiting for index ready (up to {ready_timeout}s)...")
        start = time.time()
        while True:
            desc = pc.describe_index(index_name)
            if desc.status.get("ready"):
                print(f"      ready after {time.time() - start:.1f}s")
                break
            if time.time() - start > ready_timeout:
                raise TimeoutError(
                    f"index did not become ready within {ready_timeout}s"
                )
            time.sleep(2)

        # Seed one record.
        print(f"[3/6] seeding record {record_id!r}")
        rng = np.random.default_rng(42)
        vec = rng.normal(0, 1, dim).astype(np.float32)
        vec /= np.linalg.norm(vec)
        index = pc.Index(name=index_name)
        index.upsert(
            vectors=[(record_id, vec.tolist(), {"source": "live-roundtrip"})],
            namespace=namespace,
        )
        # Pinecone serverless is eventually consistent on upsert; brief
        # pause before fetching.
        time.sleep(2)

        # Adapter-driven fetch.
        print(f"[4/6] adapter: fetch {record_id!r}")
        adapter = PineconeAdapter.connect(api_key, index_name, namespace=namespace)
        rec = adapter.get(record_id)
        assert rec.id == record_id, f"id mismatch: {rec.id}"
        assert rec.vector.shape == (dim,), f"shape mismatch: {rec.vector.shape}"
        assert rec.pin is None, "fresh record should have no pin"
        print(f"      OK, fetched {dim}-dim vector")

        print("[5/6] sign + attach + re-fetch + verify (+ tamper rejection)")
        signer = Signer.generate(key_id="vectorpin-pinecone-e2e")
        verifier = Verifier(
            public_keys={signer.key_id: signer.public_key_bytes()}
        )
        pin = signer.pin(
            source="live-roundtrip", model="bench-model", vector=rec.vector
        )
        adapter.attach_pin(record_id, pin)
        time.sleep(2)  # eventual consistency on metadata update
        refreshed = adapter.get(record_id)
        assert refreshed.pin is not None, "pin missing after attach_pin"
        assert refreshed.pin.kid == "vectorpin-pinecone-e2e", refreshed.pin.kid
        assert refreshed.pin.header.model == "bench-model"
        print(
            f"      pin attached, kid={refreshed.pin.kid!r}, "
            f"v={refreshed.pin.header.v}"
        )

        result = verifier.verify(
            refreshed.pin, source="live-roundtrip", vector=refreshed.vector
        )
        assert result, f"verify failed: {result.error}"
        print("      verify: OK")

        # Tamper check: modify the source string and confirm verify rejects.
        from vectorpin import VerifyError

        bad = verifier.verify(
            refreshed.pin, source="tampered", vector=refreshed.vector
        )
        assert not bad, "verify should have rejected tampered source"
        assert (
            bad.error is VerifyError.SOURCE_MISMATCH
        ), f"expected SOURCE_MISMATCH, got {bad.error}"
        print(f"      tamper rejection: {bad.error.name} (correct)")

        print("[6/6] end-to-end PASS")
        return 0

    finally:
        print(f"\n[cleanup] deleting index {index_name!r}")
        try:
            pc.delete_index(index_name)
            print("[cleanup] done")
        except Exception as e:
            print(
                f"[cleanup] WARN: failed to delete index: {e}",
                file=sys.stderr,
            )


if __name__ == "__main__":
    sys.exit(main())
