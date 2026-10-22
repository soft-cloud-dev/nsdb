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


def public_coverage_status(path: Path, *, headers: bool) -> tuple[str, str]:
    """Validate explicit coverage fields without exposing any source records."""
    values = {}
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            content = line.strip()
            if headers:
                if not content.startswith("# "):
                    continue
                content = content[2:]
            if "=" not in content:
                continue
            key, value = content.split("=", 1)
            if key not in ("coverage_complete", "excluded_zones"):
                continue
            if key in values:
                raise ValueError("duplicate public coverage metadata")
            values[key] = value
    status = values.get("coverage_complete"), values.get("excluded_zones")
    if status not in (("true", "none"), ("false", "gov")):
        raise ValueError("invalid public coverage metadata")
    return status


def require_comparison_break(path: Path, *, headers: bool) -> None:
    marker = "# comparison_break=true" if headers else "comparison_break=true"
    with path.open("r", encoding="utf-8") as source:
        if marker not in {line.strip() for line in source}:
            raise ValueError("partial coverage must be flagged as comparison_break")


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

    statuses = {
        name: public_coverage_status(directory / name, headers=name not in (
            "counts.txt", "changes-counts.txt"
        ))
        for name in (
            "nameservers.txt", "coverage.txt", "delegation-changes.txt",
            "nameserver-changes.txt", "counts.txt", "changes-counts.txt",
        )
    }
    if len(set(statuses.values())) != 1:
        raise ValueError("release coverage status differs across public artifacts")
    complete, excluded = statuses["coverage.txt"]
    if complete == "false":
        with (directory / "coverage.txt").open("r", encoding="utf-8") as coverage:
            if any(line.startswith("gov|") for line in coverage):
                raise ValueError("excluded gov zone present in public coverage")
        for name in ("delegation-changes.txt", "nameserver-changes.txt"):
            require_comparison_break(directory / name, headers=True)
        require_comparison_break(directory / "changes-counts.txt", headers=False)

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
