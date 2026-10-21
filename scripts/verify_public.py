#!/usr/bin/env python3
import argparse
import gzip
from pathlib import Path


def opener(path: Path):
    return gzip.open if path.suffix == ".gz" else open


def parse_snapshot(path: Path):
    k = None
    rows = {}
    with opener(path)(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("# k="):
                k = int(line.split("=", 1)[1])
            elif line and not line.startswith("#"):
                name, count = line.split("|", 1)
                rows[name] = int(count)
    if k is None:
        raise ValueError(f"missing k header: {path}")
    if any(count < k for count in rows.values()):
        raise ValueError(f"snapshot exposes a count below k: {path}")
    return k, rows


def parse_diff(path: Path):
    rows = []
    meta = {}
    with opener(path)(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("# ") and "=" in line:
                key, value = line[2:].split("=", 1)
                meta[key] = value
            elif line and not line.startswith("#"):
                rows.append(tuple(line.split("|")))
    return meta, rows


def expected(prev, cur, k):
    diff = []
    crossings = []
    for name in sorted(prev.keys() | cur.keys()):
        pv = prev.get(name)
        cv = cur.get(name)
        if pv == cv:
            continue
        ps = str(pv) if pv is not None else f"<{k}"
        cs = str(cv) if cv is not None else f"<{k}"
        delta = "NA" if pv is None or cv is None else f"{cv - pv:+d}"
        diff.append((name, ps, cs, delta))
        if pv is None:
            crossings.append(("+", name))
        elif cv is None:
            crossings.append(("-", name))
    return diff, crossings


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--previous", required=True, type=Path)
    p.add_argument("--current", required=True, type=Path)
    p.add_argument("--delegation-changes", required=True, type=Path)
    p.add_argument("--nameserver-changes", required=True, type=Path)
    args = p.parse_args()

    prev_k, prev_rows = parse_snapshot(args.previous)
    cur_k, cur_rows = parse_snapshot(args.current)
    diff_meta, actual_diff = parse_diff(args.delegation_changes)
    _, actual_crossings = parse_diff(args.nameserver_changes)

    if cur_k < prev_k:
        if diff_meta.get("public_verifiable") != "false":
            raise SystemExit("lowered k must be marked public_verifiable=false")
        print("Public verification skipped: k was lowered and the old snapshot cannot reveal newly visible rows")
        return

    prev_at_cur_k = {name: count for name, count in prev_rows.items() if count >= cur_k}
    expected_diff, expected_crossings = expected(prev_at_cur_k, cur_rows, cur_k)
    if actual_diff != expected_diff:
        raise SystemExit("delegation-changes.txt is not a pure function of the two public snapshots")
    if actual_crossings != expected_crossings:
        raise SystemExit("nameserver-changes.txt is not the threshold-crossing projection of Diff 2")

    for _, previous, current, delta in actual_diff:
        if previous.startswith("<") or current.startswith("<"):
            if delta != "NA":
                raise SystemExit("redacted Diff 2 row has a non-NA delta")
        else:
            pv = int(previous)
            cv = int(current)
            if pv < cur_k or cv < cur_k:
                raise SystemExit("Diff 2 exposed an exact value below k")
            if delta != f"{cv - pv:+d}":
                raise SystemExit("Diff 2 exact delta is incorrect")

    print("Public snapshot and both diffs verified")


if __name__ == "__main__":
    main()
