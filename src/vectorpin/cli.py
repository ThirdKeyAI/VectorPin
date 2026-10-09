# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""VectorPin CLI.

Subcommands:
  keygen          Generate an ed25519 signing key pair.
  pin             Sign a single (text, vector) pair (debug/demo).
  verify-pin      Verify a single Pin against ground-truth source/vector.
  verify-summary  Verify a signed audit summary produced by an audit command.
  audit-lancedb   Walk a LanceDB table and report on every record's pin.
  audit-chroma    Walk a Chroma collection and report on every record's pin.
  audit-qdrant    Walk a Qdrant collection and report on every record's pin.
  audit-pgvector  Walk a pgvector-equipped Postgres table and audit every pin.

Audit policy (fail closed by default):
  * an unpinned record fails the run unless ``--allow-unpinned`` is given;
  * an empty or unparseable pin field is a ``parse_error``, never "unpinned";
  * a pin that carries ``vectorpin.record_id`` must match the record it
    sits on (``--no-record-id-check`` disables);
  * ``--collection-id`` / ``--tenant-id`` / ``--expected-model`` /
    ``--expected-model-hash`` are enforced on every pinned record;
  * ``--manifest`` compares the walked record set against a signed
    collection manifest (count + Merkle root);
  * ``--sign-summary-key`` signs the JSON summary so the report itself
    is tamper-evident.

Run `vectorpin --help` for the canonical usage.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np

from vectorpin import Pin, Signer, Verifier
from vectorpin.adapters.base import verify_record
from vectorpin.manifest import (
    CollectionManifest,
    build_manifest,
    sign_audit_summary,
    verify_audit_summary,
    verify_manifest,
)

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


def _read_private_key(path: str) -> bytes:
    """Read a raw private seed, warning if the file is group/world readable.

    A readable key file is the most common way a signing key leaks on a
    shared host. The warning goes to stderr so scripted callers still
    get the key; ``VECTORPIN_QUIET_KEY_PERMS=1`` silences it for
    deployments that keep keys on permission-less filesystems.
    """
    p = Path(path)
    try:
        mode = stat.S_IMODE(p.stat().st_mode)
    except OSError:
        mode = 0
    if mode & 0o077 and os.environ.get("VECTORPIN_QUIET_KEY_PERMS") != "1":
        print(
            f"warning: private key {p} is readable by group/other (mode {mode:04o}); "
            "run chmod 600 on it",
            file=sys.stderr,
        )
    return p.read_bytes()


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


def _load_vector(path: str, json_dtype: str = "f32") -> np.ndarray:
    """Load a vector from ``.npy`` (native dtype) or ``.json``.

    JSON carries no dtype, so ``json_dtype`` declares the precision the
    serialized values represent (default ``f32``). A ``.npy`` file keeps
    its own dtype; that is the precision the verifier will check.
    """
    p = Path(path)
    if p.suffix == ".npy":
        arr = np.load(p)
        if not isinstance(arr, np.ndarray):
            raise ValueError("vector file did not contain an array")
        return arr
    if p.suffix == ".json":
        target = np.float32 if json_dtype == "f32" else np.float64
        return np.asarray(json.loads(p.read_text()), dtype=target)
    raise ValueError(f"unsupported vector file extension: {p.suffix}")


def _cmd_pin(args: argparse.Namespace) -> int:
    private_bytes = _read_private_key(args.private_key)
    signer = Signer.from_private_bytes(private_bytes, key_id=args.key_id)
    source = Path(args.source).read_text(encoding="utf-8")
    vector = _load_vector(args.vector, args.vector_dtype)
    extra: dict[str, str] = {}
    if args.record_id:
        extra["vectorpin.record_id"] = args.record_id
    if args.collection_id:
        extra["vectorpin.collection_id"] = args.collection_id
    if args.tenant_id:
        extra["vectorpin.tenant_id"] = args.tenant_id
    pin = signer.pin(
        source=source,
        model=args.model,
        vector=vector,
        model_hash=args.model_hash,
        extra=extra or None,
    )
    print(pin.to_json())
    return 0


def _cmd_verify_pin(args: argparse.Namespace) -> int:
    public_bytes = Path(args.public_key).read_bytes()
    verifier = Verifier({args.key_id: public_bytes})
    try:
        pin = Pin.from_json(Path(args.pin).read_text())
    except (ValueError, json.JSONDecodeError) as e:
        print(f"FAIL [parse_error] {e}", file=sys.stderr)
        return 2
    source = Path(args.source).read_text(encoding="utf-8") if args.source else None
    vector = _load_vector(args.vector, args.vector_dtype) if args.vector else None
    result = verifier.verify(
        pin,
        source=source,
        vector=vector,
        expected_model=args.expected_model,
        expected_model_hash=args.expected_model_hash,
        expected_record_id=args.record_id,
        expected_collection_id=args.collection_id,
        expected_tenant_id=args.tenant_id,
    )
    if result.ok:
        print("OK")
        return 0
    print(f"FAIL [{result.error.value}] {result.detail}", file=sys.stderr)
    return 2


def _cmd_verify_summary(args: argparse.Namespace) -> int:
    public_bytes = Path(args.public_key).read_bytes()
    verifier = Verifier({args.key_id: public_bytes})
    try:
        summary = json.loads(Path(args.summary).read_text())
    except (ValueError, json.JSONDecodeError) as e:
        print(f"FAIL [parse_error] {e}", file=sys.stderr)
        return 2
    result = verify_audit_summary(summary, verifier)
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
    allow_unpinned: bool = False,
    enforce_record_id: bool = True,
    expected_model: str | None = None,
    expected_model_hash: str | None = None,
    collection_id: str | None = None,
    tenant_id: str | None = None,
    manifest: CollectionManifest | None = None,
    manifest_verifier: Verifier | None = None,
    write_manifest: tuple[Path, Signer] | None = None,
    summary_signer: Signer | None = None,
) -> int:
    """Run the verify loop for any adapter and print a JSON summary.

    Returns exit code: 0 if every record passed, 1 otherwise. Fails
    closed: unpinned records count as failures unless
    ``allow_unpinned`` is set, and an empty or malformed pin field is
    always a failure. Every failure is printed to stderr as
    ``FAIL <record id> [<error>] <detail>`` so operators can locate it.

    ``manifest`` (with ``manifest_verifier`` defaulting to ``verifier``)
    is compared against the walked record set after iteration.
    ``write_manifest`` builds and signs a manifest of what was walked.
    ``summary_signer`` signs the printed summary.
    """
    total = pinned = ok = bad = unpinned = 0
    entries: list[tuple[str, str]] = []
    aborted: str | None = None
    warned_no_record_id = False
    iterator = iter(records)
    while True:
        try:
            rec = next(iterator)
        except StopIteration:
            break
        except Exception as e:  # adapter-level failure: the walk cannot continue
            aborted = f"{type(e).__name__}: {e}"
            bad += 1
            print(
                f"FAIL <iterator> [adapter_error] {aborted}; audit aborted, "
                "summary is partial",
                file=sys.stderr,
            )
            break

        total += 1
        vec_hash = rec.pin.header.vec_hash if rec.pin is not None else ""
        entries.append((rec.id, vec_hash))

        if rec.pin is None and rec.parse_error is None:
            unpinned += 1
            if allow_unpinned:
                continue
            bad += 1
            print(
                f"FAIL {rec.id} [unpinned] record has no pin "
                "(pass --allow-unpinned to tolerate during backfills)",
                file=sys.stderr,
            )
            continue
        if rec.pin is not None:
            pinned += 1
            if (
                enforce_record_id
                and "vectorpin.record_id" not in rec.pin.header.extra
                and not warned_no_record_id
            ):
                warned_no_record_id = True
                print(
                    f"warning: {rec.id}: pin carries no vectorpin.record_id; "
                    "pin-shuffle replay across records cannot be detected for "
                    "such pins (re-pin with extra={'vectorpin.record_id': ...})",
                    file=sys.stderr,
                )
        result = verify_record(
            rec,
            verifier,
            source_key=source_column,
            allow_unpinned=allow_unpinned,
            enforce_record_id=enforce_record_id,
            expected_model=expected_model,
            expected_model_hash=expected_model_hash,
            expected_collection_id=collection_id,
            expected_tenant_id=tenant_id,
        )
        if result.ok:
            ok += 1
        else:
            bad += 1
            print(f"FAIL {rec.id} [{result.error.value}] {result.detail}", file=sys.stderr)

    summary: dict[str, Any] = {
        label_field: label_value,
        "total": total,
        "pinned": pinned,
        "verified_ok": ok,
        "verification_failed": bad,
        "unpinned": unpinned,
    }
    if aborted is not None:
        summary["aborted"] = aborted

    if manifest is not None:
        mres = verify_manifest(
            manifest,
            manifest_verifier or verifier,
            entries,
            expected_collection_id=collection_id,
        )
        summary["manifest"] = mres.error.value
        if not mres.ok:
            bad += 1
            summary["verification_failed"] = bad
            print(f"FAIL <manifest> [{mres.error.value}] {mres.detail}", file=sys.stderr)

    if write_manifest is not None:
        path, signer = write_manifest
        built = build_manifest(signer, collection_id or label_value, entries)
        path.write_text(built.to_json() + "\n")
        summary["manifest_written"] = str(path)
        print(f"wrote manifest {path} ({built.count} records)", file=sys.stderr)

    if summary_signer is not None:
        summary = sign_audit_summary(summary, summary_signer)

    print(json.dumps(summary, indent=2))
    return 1 if bad else 0


def _audit_policy_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    """Translate the shared audit flags into ``_audit_loop`` keyword args."""
    kwargs: dict[str, Any] = {
        "allow_unpinned": args.allow_unpinned,
        "enforce_record_id": not args.no_record_id_check,
        "expected_model": args.expected_model,
        "expected_model_hash": args.expected_model_hash,
        "collection_id": args.collection_id,
        "tenant_id": args.tenant_id,
    }
    if args.manifest:
        kwargs["manifest"] = CollectionManifest.from_json(Path(args.manifest).read_text())
        if args.manifest_public_key:
            kid = args.manifest_key_id or kwargs["manifest"].kid
            kwargs["manifest_verifier"] = Verifier(
                {kid: Path(args.manifest_public_key).read_bytes()}
            )
    if args.write_manifest:
        if not args.manifest_key or not args.manifest_key_id:
            raise SystemExit(
                "--write-manifest requires --manifest-key and --manifest-key-id"
            )
        signer = Signer.from_private_bytes(
            _read_private_key(args.manifest_key), key_id=args.manifest_key_id
        )
        kwargs["write_manifest"] = (Path(args.write_manifest), signer)
    if args.sign_summary_key:
        if not args.sign_summary_key_id:
            raise SystemExit("--sign-summary-key requires --sign-summary-key-id")
        kwargs["summary_signer"] = Signer.from_private_bytes(
            _read_private_key(args.sign_summary_key), key_id=args.sign_summary_key_id
        )
    return kwargs


def _cmd_audit_qdrant(args: argparse.Namespace) -> int:
    from vectorpin.adapters.qdrant import QdrantAdapter

    public_bytes = Path(args.public_key).read_bytes()
    verifier = Verifier({args.key_id: public_bytes})
    adapter = QdrantAdapter.connect(
        args.url,
        args.collection,
        api_key=args.api_key,
        vector_dtype=np.float32 if args.vector_dtype == "f32" else np.float64,
    )
    return _audit_loop(
        adapter.iter_records(batch_size=args.batch_size),
        verifier,
        source_column=args.source_payload_key,
        label_field="collection",
        label_value=args.collection,
        **_audit_policy_kwargs(args),
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
        **_audit_policy_kwargs(args),
    )


def _cmd_audit_pgvector(args: argparse.Namespace) -> int:
    from vectorpin.adapters.pgvector import PgVectorAdapter

    public_bytes = Path(args.public_key).read_bytes()
    verifier = Verifier({args.key_id: public_bytes})
    adapter = PgVectorAdapter.connect(
        args.dsn,
        args.table,
        id_column=args.id_column,
        vector_column=args.vector_column,
        pin_column=args.pin_column,
    )
    return _audit_loop(
        adapter.iter_records(batch_size=args.batch_size),
        verifier,
        source_column=None,
        label_field="table",
        label_value=args.table,
        **_audit_policy_kwargs(args),
    )


def _parse_headers(pairs: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for pair in pairs or []:
        name, sep, value = pair.partition("=")
        if not sep or not name.strip():
            raise SystemExit(f"--header expects NAME=VALUE; got {pair!r}")
        headers[name.strip()] = value
    return headers


def _cmd_audit_chroma(args: argparse.Namespace) -> int:
    from vectorpin.adapters.chroma import ChromaAdapter

    public_bytes = Path(args.public_key).read_bytes()
    verifier = Verifier({args.key_id: public_bytes})
    if args.host:
        adapter = ChromaAdapter.connect_http(
            host=args.host,
            port=args.port,
            collection_name=args.collection,
            ssl=args.ssl,
            headers=_parse_headers(args.header) or None,
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
        **_audit_policy_kwargs(args),
    )


def _add_audit_common_args(p: argparse.ArgumentParser) -> None:
    """Flags shared by every audit-* command (verification policy)."""
    p.add_argument("--public-key", required=True, help="path to .pub key file")
    p.add_argument("--key-id", required=True)
    p.add_argument("--batch-size", type=int, default=256)
    policy = p.add_argument_group("verification policy")
    policy.add_argument(
        "--allow-unpinned",
        action="store_true",
        default=False,
        help=(
            "do not fail the run on records that carry no pin (for partial "
            "backfills). Default: unpinned records fail, because an attacker "
            "who can rewrite a vector can delete its pin just as easily."
        ),
    )
    policy.add_argument(
        "--no-record-id-check",
        action="store_true",
        default=False,
        help=(
            "do not require a pin's vectorpin.record_id to equal the id of the "
            "record it is stored on"
        ),
    )
    policy.add_argument(
        "--collection-id",
        default=None,
        help="expected vectorpin.collection_id; every pin must carry exactly this value",
    )
    policy.add_argument(
        "--tenant-id",
        default=None,
        help="expected vectorpin.tenant_id; every pin must carry exactly this value",
    )
    policy.add_argument(
        "--expected-model",
        default=None,
        help="every pin's model field must equal this identifier",
    )
    policy.add_argument(
        "--expected-model-hash",
        default=None,
        help="every pin's model_hash must equal this sha256:<hex> value",
    )
    manifest = p.add_argument_group("collection manifest")
    manifest.add_argument(
        "--manifest",
        default=None,
        help=(
            "path to a signed collection manifest; the walked record set must "
            "match its count and Merkle root"
        ),
    )
    manifest.add_argument(
        "--manifest-public-key",
        default=None,
        help="public key that signed the manifest (default: the audit --public-key)",
    )
    manifest.add_argument(
        "--manifest-key-id",
        default=None,
        help="key id for --manifest-public-key / --manifest-key",
    )
    manifest.add_argument(
        "--write-manifest",
        default=None,
        help=(
            "write a signed manifest of the walked record set to this path "
            "(run immediately after ingestion; requires --manifest-key)"
        ),
    )
    manifest.add_argument("--manifest-key", default=None, help="path to .priv key file")
    summary = p.add_argument_group("signed summary")
    summary.add_argument(
        "--sign-summary-key",
        default=None,
        help="path to a .priv key; the JSON summary is signed with it",
    )
    summary.add_argument("--sign-summary-key-id", default=None)


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
    p_pin.add_argument("--model-hash", default=None, help="optional sha256:<hex> of the weights")
    p_pin.add_argument("--source", required=True, help="path to source text file")
    p_pin.add_argument("--vector", required=True, help="path to vector (.npy or .json)")
    p_pin.add_argument(
        "--vector-dtype",
        choices=("f32", "f64"),
        default="f32",
        help=(
            "precision a .json vector represents (default f32); .npy files keep "
            "their own dtype. The pin is signed under the loaded array's dtype."
        ),
    )
    p_pin.add_argument("--record-id", default=None, help="bind vectorpin.record_id")
    p_pin.add_argument("--collection-id", default=None, help="bind vectorpin.collection_id")
    p_pin.add_argument("--tenant-id", default=None, help="bind vectorpin.tenant_id")
    p_pin.set_defaults(func=_cmd_pin)

    p_verify = sub.add_parser("verify-pin", help="verify a Pin against ground-truth")
    p_verify.add_argument("--public-key", required=True, help="path to .pub key file")
    p_verify.add_argument("--key-id", required=True)
    p_verify.add_argument("--pin", required=True, help="path to pin JSON file")
    p_verify.add_argument("--source", help="optional path to source text for full verification")
    p_verify.add_argument("--vector", help="optional path to vector for full verification")
    p_verify.add_argument(
        "--vector-dtype",
        choices=("f32", "f64"),
        default="f32",
        help="precision a .json vector represents (default f32); .npy files keep their dtype",
    )
    p_verify.add_argument("--expected-model", default=None)
    p_verify.add_argument("--expected-model-hash", default=None)
    p_verify.add_argument("--record-id", default=None, help="expected vectorpin.record_id")
    p_verify.add_argument("--collection-id", default=None, help="expected vectorpin.collection_id")
    p_verify.add_argument("--tenant-id", default=None, help="expected vectorpin.tenant_id")
    p_verify.set_defaults(func=_cmd_verify_pin)

    p_vs = sub.add_parser("verify-summary", help="verify a signed audit summary")
    p_vs.add_argument("--public-key", required=True, help="path to .pub key file")
    p_vs.add_argument("--key-id", required=True)
    p_vs.add_argument("--summary", required=True, help="path to the summary JSON file")
    p_vs.set_defaults(func=_cmd_verify_summary)

    p_audit_q = sub.add_parser("audit-qdrant", help="audit every pin in a Qdrant collection")
    p_audit_q.add_argument("--url", required=True, help="qdrant URL, e.g. http://localhost:6333")
    p_audit_q.add_argument("--collection", required=True)
    p_audit_q.add_argument("--api-key", default=None)
    p_audit_q.add_argument(
        "--vector-dtype",
        choices=("f32", "f64"),
        default="f32",
        help="element type the collection persists (Qdrant default: f32)",
    )
    p_audit_q.add_argument(
        "--source-payload-key",
        default=None,
        help="optional Qdrant payload key holding the source text; if set, source is verified too",
    )
    _add_audit_common_args(p_audit_q)
    p_audit_q.set_defaults(func=_cmd_audit_qdrant)

    p_audit_l = sub.add_parser("audit-lancedb", help="audit every pin in a LanceDB table")
    p_audit_l.add_argument(
        "--uri",
        required=True,
        help="lancedb URI: a directory path, s3://, gs://, or LanceDB Cloud connection string",
    )
    p_audit_l.add_argument("--table", required=True)
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
    _add_audit_common_args(p_audit_l)
    p_audit_l.set_defaults(func=_cmd_audit_lancedb)

    p_audit_c = sub.add_parser("audit-chroma", help="audit every pin in a Chroma collection")
    p_audit_c.add_argument("--collection", required=True)
    p_audit_c.add_argument("--path", default=None, help="path for a PersistentClient")
    p_audit_c.add_argument("--host", default=None, help="host for an HttpClient")
    p_audit_c.add_argument("--port", type=int, default=8000)
    p_audit_c.add_argument("--ssl", action="store_true", default=False)
    p_audit_c.add_argument(
        "--header",
        action="append",
        default=None,
        metavar="NAME=VALUE",
        help=(
            "HTTP header for the HttpClient (repeatable). Credentials are refused over "
            "plaintext to a non-loopback host unless --ssl is set."
        ),
    )
    p_audit_c.add_argument(
        "--source-metadata-key",
        default=None,
        help="optional metadata key holding the source text; if set, source is verified too",
    )
    _add_audit_common_args(p_audit_c)
    p_audit_c.set_defaults(func=_cmd_audit_chroma)

    p_audit_p = sub.add_parser(
        "audit-pgvector",
        help="audit every pin in a pgvector-equipped Postgres table",
    )
    p_audit_p.add_argument(
        "--dsn",
        required=True,
        help=(
            "postgres DSN, e.g. postgresql://user:pass@host:5432/db?sslmode=require. "
            "Non-loopback hosts require sslmode=require (or stronger) unless "
            "VECTORPIN_ALLOW_INSECURE_HTTP=1 is set."
        ),
    )
    p_audit_p.add_argument("--table", required=True)
    p_audit_p.add_argument("--id-column", default="id")
    p_audit_p.add_argument("--vector-column", default="embedding")
    p_audit_p.add_argument(
        "--pin-column",
        default="vectorpin",
        help="JSONB or TEXT column holding the pin payload (default: vectorpin)",
    )
    _add_audit_common_args(p_audit_p)
    p_audit_p.set_defaults(func=_cmd_audit_pgvector)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
