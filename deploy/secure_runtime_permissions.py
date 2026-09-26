"""Apply runtime file ownership without following replaceable path symlinks."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path


def secure_runtime_permissions(
    path: str | Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    allow_missing: bool = False,
) -> bool:
    required = ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required) or not hasattr(os, "fchown") or not hasattr(os, "fchmod"):
        raise RuntimeError("descriptor-safe permissions require POSIX")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(os.fspath(path), flags)
    except FileNotFoundError:
        if allow_missing:
            return False
        raise

    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"runtime path is not a regular file: {path}")
        os.fchown(fd, int(uid), int(gid))
        os.fchmod(fd, int(mode))
    finally:
        os.close(fd)
    return True


def _octal_mode(value: str) -> int:
    try:
        mode = int(value, 8)
    except ValueError:
        raise argparse.ArgumentTypeError("mode must be octal") from None
    if not 0 <= mode <= 0o7777:
        raise argparse.ArgumentTypeError("mode is outside the supported range")
    return mode


def main() -> int:
    try:
        import grp
        import pwd
    except ImportError:
        raise SystemExit("descriptor-safe permissions require POSIX") from None

    parser = argparse.ArgumentParser(description="Secure one runtime file without following symlinks")
    parser.add_argument("path", type=Path)
    parser.add_argument("--user", required=True)
    parser.add_argument("--group", required=True)
    parser.add_argument("--mode", required=True, type=_octal_mode)
    parser.add_argument("--optional", action="store_true")
    args = parser.parse_args()

    secure_runtime_permissions(
        args.path,
        uid=pwd.getpwnam(args.user).pw_uid,
        gid=grp.getgrnam(args.group).gr_gid,
        mode=args.mode,
        allow_missing=args.optional,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
