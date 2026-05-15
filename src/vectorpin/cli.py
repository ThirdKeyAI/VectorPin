# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""VectorPin CLI.

Subcommands:
  keygen          Generate an ed25519 signing key pair.
  pin             Sign a single (text, vector) pair (debug/demo).
  verify-pin      Verify a single Pin against ground-truth source/vector.
  audit-lancedb   Walk a LanceDB table and report on every record's pin.
  audit-chroma    Walk a Chroma collection and report on every record's pin.
  audit-qdrant    Walk a Qdrant collection and report on every record's pin.

Run `vectorpin --help` for the canonical usage.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import numpy as np

from vectorpin import Pin, Signer, Verifier

if TYPE_CHECKING:
    from vectorpin.adapters.base import PinnedRecord


def _write_private_key(path: Path, data: bytes) -> None:
    """Write a private key with mode 0600 atomically.

    Uses O_EXCL so we never silently clobber an existing key on disk —
    overwriting key material is almost always a bug, and a fresh keygen
    against a populated directory should fail loudly.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError as e:
        raise FileExistsError(
            f"refusing to overwrite existing private key at {path}"
        ) from e
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _cmd_keygen(args: argparse.Namespace) -> int:
    signer = Signer.generate(key_id=args.key_id)
    out = Path(args.output)
    # mkdir with restrictive mode; if the directory already exists we
    # leave its mode alone (operator's call) but tighten new dirs.
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    priv_path = out / f"{args.key_id}.priv"
    pub_path = out / f"{args.key_id}.pub"
    _write_private_key(priv_path, signer.private_key_bytes())
    pub_path.write_bytes(signer.public_key_bytes())
    # Public key is intentionally world-readable, but be explicit so we
    # don't inherit a surprising umask.
    os.chmod(pub_path, 0o644)
    print(f"wrote {priv_path}  (KEEP SECRET)", file=sys.stderr)
    print(f"wrote {pub_path}")
    return 0


def _load_vector(path: str) -> np.ndarray:
    p = Path(path)
    if p.suffix == ".npy":
        return np.load(p)
    if p.suffix == ".json":
        return np.asarray(json.loads(p.read_text()), dtype=np.float32)
    raise ValueError(f"unsupported vector file extension: {p.suffix}")


def _cmd_pin(args: argparse.Namespace) -> int:
    private_bytes = Path(args.private_key).read_bytes()
    signer = Signer.from_private_bytes(private_bytes, key_id=args.key_id)
    source = Path(args.source).read_text(encoding="utf-8")
    vector = _load_vector(args.vector)
    pin = signer.pin(source=source, model=args.model, vector=vector)
    print(pin.to_json())
    return 0


def _cmd_verify_pin(args: argparse.Namespace) -> int:
    public_bytes = Path(args.public_key).read_bytes()
    verifier = Verifier({args.key_id: public_bytes})
    pin = Pin.from_json(Path(args.pin).read_text())
    source = Path(args.source).read_text(encoding="utf-8") if args.source else None
    vector = _load_vector(args.vector) if args.vector else None
    result = verifier.verify(pin, source=source, vector=vector)
    if result.ok:
        print("OK")
        return 0
    print(f"FAIL [{result.error.value}] {result.detail}", file=sys.stderr)
    return 2


def _audit_loop(
    records: Iterator[PinnedRecord],
    verifier: Verifier,
    *,
    source_column: str | None,
    label_field: str,
    label_value: str,
) -> int:
    """Run the verify loop for any adapter and print a JSON summary.

    Returns exit code: 0 if every pinned record verified, 1 if any
    verification failed. Unpinned records are reported but do not
    fail the run by themselves; operators who want stricter behavior
    can grep `unpinned` from the JSON summary in CI.
    """
    total = pinned = ok = bad = unpinned = 0
    # Drive the iterator manually so a malformed record (e.g. a Pin
    # whose JSON fails strict validation) raises during `next()` and we
    # can fail-open on that single row instead of aborting the audit.
    iterator = iter(records)
    while True:
        try:
            rec = next(iterator)
        except StopIteration:
            break
        except (ValueError, json.JSONDecodeError, KeyError) as e:
            total += 1
            bad += 1
            print(
                f"FAIL <unknown> [parse_error] {e}",
                file=sys.stderr,
            )
            continue

        total += 1
        if rec.pin is None:
            unpinned += 1
            continue
        pinned += 1
        verify_kwargs: dict[str, object] = {"vector": rec.vector}
        if source_column is not None:
            src = rec.metadata.get(source_column)
            if src is None:
                bad += 1
                print(
                    f"FAIL {rec.id} [missing_source_column] "
                    f"record has no {source_column!r} field",
                    file=sys.stderr,
                )
                continue
            verify_kwargs["source"] = str(src)
        try:
            result = verifier.verify(rec.pin, **verify_kwargs)  # type: ignore[arg-type]
        except (ValueError, KeyError) as e:
            bad += 1
            print(f"FAIL {rec.id} [parse_error] {e}", file=sys.stderr)
            continue
        if result.ok:
            ok += 1
        else:
            bad += 1
            print(f"FAIL {rec.id} [{result.error.value}] {result.detail}", file=sys.stderr)

    print(
        json.dumps(
            {
                label_field: label_value,
                "total": total,
                "pinned": pinned,
                "verified_ok": ok,
                "verification_failed": bad,
                "unpinned": unpinned,
            },
            indent=2,
        )
    )
    return 1 if bad else 0


def _cmd_audit_qdrant(args: argparse.Namespace) -> int:
    from vectorpin.adapters.qdrant import QdrantAdapter

    public_bytes = Path(args.public_key).read_bytes()
    verifier = Verifier({args.key_id: public_bytes})
    adapter = QdrantAdapter.connect(args.url, args.collection, api_key=args.api_key)
    return _audit_loop(
        adapter.iter_records(batch_size=args.batch_size),
        verifier,
        source_column=args.source_payload_key,
        label_field="collection",
        label_value=args.collection,
    )


def _cmd_audit_lancedb(args: argparse.Namespace) -> int:
    from vectorpin.adapters.lancedb import LanceDBAdapter

    public_bytes = Path(args.public_key).read_bytes()
    verifier = Verifier({args.key_id: public_bytes})
    adapter = LanceDBAdapter.connect(
        args.uri,
        args.table,
        id_column=args.id_column,
        vector_column=args.vector_column,
    )
    return _audit_loop(
        adapter.iter_records(batch_size=args.batch_size),
        verifier,
        source_column=args.source_column,
        label_field="table",
        label_value=args.table,
    )


def _cmd_audit_chroma(args: argparse.Namespace) -> int:
    from vectorpin.adapters.chroma import ChromaAdapter

    public_bytes = Path(args.public_key).read_bytes()
    verifier = Verifier({args.key_id: public_bytes})
    if args.host:
        adapter = ChromaAdapter.connect_http(
            host=args.host, port=args.port, collection_name=args.collection, ssl=args.ssl
        )
    elif args.path:
        adapter = ChromaAdapter.connect_persistent(args.path, args.collection)
    else:
        print(
            "audit-chroma requires either --path (persistent) or --host (HTTP)",
            file=sys.stderr,
        )
        return 2
    return _audit_loop(
        adapter.iter_records(batch_size=args.batch_size),
        verifier,
        source_column=args.source_metadata_key,
        label_field="collection",
        label_value=args.collection,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vectorpin",
        description="Verifiable integrity for AI embedding stores.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_keygen = sub.add_parser("keygen", help="generate an ed25519 signing key pair")
    p_keygen.add_argument("--key-id", required=True, help="identifier for the new key")
    p_keygen.add_argument("--output", default="keys", help="output directory (default: ./keys)")
    p_keygen.set_defaults(func=_cmd_keygen)

    p_pin = sub.add_parser("pin", help="sign a single (text, vector) pair")
    p_pin.add_argument("--private-key", required=True, help="path to .priv key file")
    p_pin.add_argument("--key-id", required=True)
    p_pin.add_argument("--model", required=True, help="embedding model identifier")
    p_pin.add_argument("--source", required=True, help="path to source text file")
    p_pin.add_argument("--vector", required=True, help="path to vector (.npy or .json)")
    p_pin.set_defaults(func=_cmd_pin)

    p_verify = sub.add_parser("verify-pin", help="verify a Pin against ground-truth")
    p_verify.add_argument("--public-key", required=True, help="path to .pub key file")
    p_verify.add_argument("--key-id", required=True)
    p_verify.add_argument("--pin", required=True, help="path to pin JSON file")
    p_verify.add_argument("--source", help="optional path to source text for full verification")
    p_verify.add_argument("--vector", help="optional path to vector for full verification")
    p_verify.set_defaults(func=_cmd_verify_pin)

    p_audit_q = sub.add_parser("audit-qdrant", help="audit every pin in a Qdrant collection")
    p_audit_q.add_argument("--url", required=True, help="qdrant URL, e.g. http://localhost:6333")
    p_audit_q.add_argument("--collection", required=True)
    p_audit_q.add_argument("--public-key", required=True)
    p_audit_q.add_argument("--key-id", required=True)
    p_audit_q.add_argument("--api-key", default=None)
    p_audit_q.add_argument("--batch-size", type=int, default=256)
    p_audit_q.add_argument(
        "--source-payload-key",
        default=None,
        help="optional Qdrant payload key holding the source text; if set, source is verified too",
    )
    p_audit_q.set_defaults(func=_cmd_audit_qdrant)

    p_audit_l = sub.add_parser("audit-lancedb", help="audit every pin in a LanceDB table")
    p_audit_l.add_argument(
        "--uri",
        required=True,
        help="lancedb URI: a directory path, s3://, gs://, or LanceDB Cloud connection string",
    )
    p_audit_l.add_argument("--table", required=True)
    p_audit_l.add_argument("--public-key", required=True)
    p_audit_l.add_argument("--key-id", required=True)
    p_audit_l.add_argument("--id-column", default="id")
    p_audit_l.add_argument("--vector-column", default="vector")
    p_audit_l.add_argument(
        "--source-column",
        default=None,
        help=(
            "optional column holding the source text; if set, source is verified too. "
            "For Symbiont's default schema use --source-column content."
        ),
    )
    p_audit_l.add_argument("--batch-size", type=int, default=256)
    p_audit_l.set_defaults(func=_cmd_audit_lancedb)

    p_audit_c = sub.add_parser("audit-chroma", help="audit every pin in a Chroma collection")
    p_audit_c.add_argument("--collection", required=True)
    p_audit_c.add_argument("--public-key", required=True)
    p_audit_c.add_argument("--key-id", required=True)
    p_audit_c.add_argument("--path", default=None, help="path for a PersistentClient")
    p_audit_c.add_argument("--host", default=None, help="host for an HttpClient")
    p_audit_c.add_argument("--port", type=int, default=8000)
    p_audit_c.add_argument("--ssl", action="store_true", default=False)
    p_audit_c.add_argument(
        "--source-metadata-key",
        default=None,
        help="optional metadata key holding the source text; if set, source is verified too",
    )
    p_audit_c.add_argument("--batch-size", type=int, default=256)
    p_audit_c.set_defaults(func=_cmd_audit_chroma)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
