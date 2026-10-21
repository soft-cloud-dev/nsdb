#!/usr/bin/env python3
import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

SOURCE = "https://www.iana.org/assignments/locally-served-dns-zones/locally-served-dns-zones.txt"
ZONE_RE = re.compile(r"^\s*([A-Z0-9_.-]+\.ARPA)\.?\s+", re.IGNORECASE)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()

    response = requests.get(SOURCE, timeout=60)
    response.raise_for_status()
    zones = set()
    for line in response.text.splitlines():
        match = ZONE_RE.match(line)
        if match:
            zones.add(match.group(1).lower().rstrip("."))
    if len(zones) < 10:
        raise SystemExit(f"unexpectedly small IANA locally-served zone set: {len(zones)}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# source={SOURCE}\n")
        fh.write(f"# fetched={datetime.now(timezone.utc).date().isoformat()}\n")
        fh.write("# format=zone\n")
        for zone in sorted(zones):
            fh.write(zone + "\n")


if __name__ == "__main__":
    main()
