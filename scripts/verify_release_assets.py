#!/usr/bin/env python3
"""Fail closed unless the release payload is complete, consistent and public-only."""
import argparse
import gzip
import hashlib
import re
from pathlib import Path


ARTIFACTS = (
    "nameservers.txt",
    "nameservers.txt.gz",
    "delegation-changes.txt",
    "delegation-changes.txt.gz",
    "nameserver-changes.txt",
    "nameserver-changes.txt.gz",
    "coverage.txt",
    "special-zones.txt",
    "counts.txt",
    "changes-counts.txt",
)
GZIP_PAIRS = (
    ("nameservers.txt", "nameservers.txt.gz"),
    ("delegation-changes.txt", "delegation-changes.txt.gz"),
    ("nameserver-changes.txt", "nameserver-changes.txt.gz"),
)
CHECKSUM_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(directory: Path) -> None:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("release output directory is missing or is a symlink")

    expected = set(ARTIFACTS) | {"SHA256SUMS"}
    present = {entry.name for entry in directory.iterdir()}
    if present != expected:
        raise ValueError(
            f"release file set differs from allowlist: "
            f"missing={sorted(expected - present)}, unexpected={sorted(present - expected)}"
        )

    for name in expected:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"release artifact is not a regular file: {name}")

    checksums = {}
    with (directory / "SHA256SUMS").open("r", encoding="ascii") as source:
        for line in source:
            match = CHECKSUM_LINE.fullmatch(line.rstrip("\n"))
            if match is None:
                raise ValueError("malformed SHA256SUMS entry")
            digest, name = match.groups()
            if name in checksums:
                raise ValueError(f"duplicate SHA256SUMS entry: {name}")
            checksums[name] = digest

    if set(checksums) != set(ARTIFACTS):
        raise ValueError("SHA256SUMS must list exactly the ten public artifacts")

    for name, expected_digest in checksums.items():
        if file_sha256(directory / name) != expected_digest:
            raise ValueError(f"SHA-256 mismatch: {name}")

    for name, compressed in GZIP_PAIRS:
        with (directory / compressed).open("rb") as source:
            header = source.read(10)
        if (
            len(header) != 10
            or header[:3] != b"\x1f\x8b\x08"
            or header[3] != 0
            or header[4:8] != b"\x00\x00\x00\x00"
        ):
            raise ValueError(f"gzip header is not deterministic: {compressed}")
        with (directory / name).open("rb") as plain, gzip.open(directory / compressed, "rb") as zipped:
            while True:
                original = plain.read(1024 * 1024)
                unpacked = zipped.read(1024 * 1024)
                if original != unpacked:
                    raise ValueError(f"gzip content differs from public text: {compressed}")
                if not original:
                    break


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=Path, default=Path("dist"))
    args = parser.parse_args()
    try:
        verify(args.dir)
    except (OSError, ValueError, EOFError) as exc:
        raise SystemExit(str(exc)) from exc
    print("Release allowlist, SHA256SUMS and deterministic gzip contents verified")


if __name__ == "__main__":
    main()
