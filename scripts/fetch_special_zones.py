#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

import requests

SOURCE = "https://www.iana.org/assignments/locally-served-dns-zones/locally-served-dns-zones.txt"
ZONE_RE = re.compile(r"^\s*([A-Z0-9_.-]+\.ARPA)\.?\s+", re.IGNORECASE)
LAST_UPDATED_RE = re.compile(r"^\s*Last Updated\s*$", re.IGNORECASE)
DATE_RE = re.compile(r"^\s*(\d{4}-\d{2}-\d{2})\s*$")


def parse_registry(text: str) -> tuple[str, list[str]]:
    lines = text.splitlines()
    zones = set()
    last_updated = None

    for index, line in enumerate(lines):
        match = ZONE_RE.match(line)
        if match:
            zones.add(match.group(1).lower().rstrip("."))

        if LAST_UPDATED_RE.match(line):
            for candidate in lines[index + 1 : index + 4]:
                date_match = DATE_RE.match(candidate)
                if date_match:
                    last_updated = date_match.group(1)
                    break

    if len(zones) < 100:
        raise ValueError(f"unexpectedly small IANA locally-served zone set: {len(zones)}")
    if last_updated is None:
        raise ValueError("IANA registry Last Updated date was not found")

    return last_updated, sorted(zones)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source", default=SOURCE)
    args = parser.parse_args()

    response = requests.get(args.source, timeout=60)
    response.raise_for_status()
    last_updated, zones = parse_registry(response.text)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# source={args.source}\n")
        fh.write(f"# iana_last_updated={last_updated}\n")
        fh.write("# format=zone\n")
        for zone in zones:
            fh.write(zone + "\n")


if __name__ == "__main__":
    main()
