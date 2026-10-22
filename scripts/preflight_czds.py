#!/usr/bin/env python3
"""Validate nonstandard CZDS zone headers before an expensive full aggregation.

This scan uses a discard-only aggregation sink: it does not retain raw
delegations, nameserver counts, or intermediate SQLite databases.
"""
import argparse
import json
import tarfile
from pathlib import Path

from build_nsdb import (
    ZoneValidationError,
    classify_record_fields,
    public_validation_code,
    infer_apex_from_filename,
    load_special_zones,
    open_text_stream,
    process_input,
)


class DiscardAggregate:
    def add(self, nameserver: str) -> None:
        # Never persist or print a nameserver or a domain-to-NS relationship.
        pass


def has_nonleading_soa(path: Path) -> bool:
    if tarfile.is_tarfile(path):
        # Tar members use their own internal filenames and SOA handling.
        # Tar archives are parsed by the main build; do not expand here.
        return False

    with open_text_stream(path) as source:
        first = source.readline().rstrip("\r\n")
    fields = first.split("\t", 4)
    if len(fields) != 5:
        raise ZoneValidationError(classify_record_fields(first), "first zone record does not have five tab-separated fields")
    return fields[3].lower() != "soa" or fields[2].lower() != "in"


def preflight(zones_dir: Path, special_zones_file: Path) -> int:
    manifest = json.loads((zones_dir / "manifest.json").read_text(encoding="utf-8"))
    entries = manifest.get("files", [])
    if not entries:
        raise ValueError("CZDS manifest contains no files")

    special_zones = load_special_zones(special_zones_file)
    completed = 0
    for entry in entries:
        filename = entry["filename"]
        if Path(filename).name != filename:
            raise ValueError("manifest contains a non-basename path")
        path = zones_dir / filename
        if not path.is_file():
            raise ValueError(f"missing zone file: {filename}")
        if not has_nonleading_soa(path):
            continue
        if infer_apex_from_filename(filename) is None:
            raise ZoneValidationError("apex_hint_unavailable", f"no trusted apex hint for nonstandard zone: {filename}")

        print(f"Checking non-leading SOA zone: {filename}", flush=True)
        try:
            process_input(path, special_zones, DiscardAggregate())
        except Exception as exc:
            # Avoid accidentally exposing a licensed zone record in the
            # publicly readable GitHub Actions logs.
            raise SystemExit(
                f"failed non-leading SOA preflight for {filename} "
                f"(reason={public_validation_code(exc)})"
            ) from None
        completed += 1
        print(f"Non-leading SOA validated: {filename}", flush=True)

    print(f"Non-leading SOA preflight completed: {completed} files", flush=True)
    return completed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zones-dir", type=Path, required=True)
    parser.add_argument("--special-zones", type=Path, required=True)
    args = parser.parse_args()

    try:
        preflight(args.zones_dir, args.special_zones)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(
            f"NSDB preflight failed (reason={public_validation_code(exc)})"
        ) from None


if __name__ == "__main__":
    main()
