# Copyright 2025 Jascha Wanger / Tarnover, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for `vectorpin keygen` filesystem permission hardening.

The private key file must land at 0600 regardless of umask, and the
command must refuse to clobber an existing key. The public key is set
to 0644 explicitly.
"""

from __future__ import annotations

import io
import os
import stat
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from vectorpin.cli import build_parser


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            args = build_parser().parse_args(argv)
            code = int(args.func(args))
        except SystemExit as e:
            code = int(e.code) if isinstance(e.code, int) else 1
    return code, out.getvalue(), err.getvalue()


def test_keygen_private_key_is_mode_0600(tmp_path: Path) -> None:
    """Even with a permissive umask, the .priv file must end up at 0600."""
    # Force a permissive umask to prove we don't rely on it.
    prev_umask = os.umask(0o000)
    try:
        code, _out, _err = _run_cli(
            ["keygen", "--key-id", "test-key", "--output", str(tmp_path)]
        )
    finally:
        os.umask(prev_umask)

    assert code == 0
    priv = tmp_path / "test-key.priv"
    pub = tmp_path / "test-key.pub"
    assert priv.exists()
    assert pub.exists()

    priv_mode = stat.S_IMODE(priv.stat().st_mode)
    pub_mode = stat.S_IMODE(pub.stat().st_mode)
    assert oct(priv_mode) == "0o600", f"private key mode is {oct(priv_mode)}"
    assert oct(pub_mode) == "0o644", f"public key mode is {oct(pub_mode)}"


def test_keygen_refuses_to_overwrite_existing_private_key(tmp_path: Path) -> None:
    """A second keygen against the same directory must fail loudly."""
    code, _out, _err = _run_cli(
        ["keygen", "--key-id", "dup", "--output", str(tmp_path)]
    )
    assert code == 0

    # Second invocation must raise (not silently clobber).
    with pytest.raises(FileExistsError):
        _run_cli(["keygen", "--key-id", "dup", "--output", str(tmp_path)])
