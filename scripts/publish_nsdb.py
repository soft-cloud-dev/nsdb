#!/usr/bin/env python3
import argparse
import gzip
import shutil
from pathlib import Path


def parse_k_header(path: Path) -> int:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("# k="):
                return int(line.split("=", 1)[1].strip())
            if not line.startswith("#"):
                break
    raise ValueError(f"missing # k= header in {path}")


def iter_count_rows(path: Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            name, value = line.split("|", 1)
            yield name, int(value)


def load_visible(path: Path, k: int) -> dict[str, int]:
    return {name: count for name, count in iter_count_rows(path) if count >= k}


def rethreshold_public(path: Path, k: int) -> dict[str, int]:
    old_k = parse_k_header(path)
    if k < old_k:
        raise ValueError(f"cannot lower k from public data: previous={old_k}, current={k}")
    return load_visible(path, k)


def build_diff(prev: dict[str, int], cur: dict[str, int], k: int):
    changes = []
    crossings = []
    for name in sorted(prev.keys() | cur.keys()):
        pv = prev.get(name)
        cv = cur.get(name)
        if pv == cv:
            continue
        if pv is None and cv is None:
            continue
        previous = str(pv) if pv is not None else f"<{k}"
        current = str(cv) if cv is not None else f"<{k}"
        delta = str(cv - pv) if pv is not None and cv is not None else "NA"
        if delta != "NA" and not delta.startswith("-"):
            delta = "+" + delta
        changes.append((name, previous, current, delta))
        if pv is None and cv is not None:
            crossings.append(("+", name))
        elif pv is not None and cv is None:
            crossings.append(("-", name))
    return changes, crossings


def write_gzip_copy(path: Path):
    with open(path, "rb") as src, open(str(path) + ".gz", "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as dst:
            shutil.copyfileobj(src, dst)


def write_public_snapshot(path: Path, counts: dict[str, int], k: int, current_tag: str):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# k={k}\n")
        fh.write(f"# snapshot={current_tag}\n")
        fh.write("# format=nameserver|delegations\n")
        for name in sorted(counts):
            fh.write(f"{name}|{counts[name]}\n")
    write_gzip_copy(path)


def load_key_values(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    out = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            out[key] = value
    return out


def load_coverage(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    zones = set()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            zones.add(line.split("|", 1)[0])
    return zones


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--current-private", required=True, type=Path)
    p.add_argument("--current-full-counts", required=True, type=Path)
    p.add_argument("--current-coverage", required=True, type=Path)
    p.add_argument("--previous-private", type=Path)
    p.add_argument("--previous-public", type=Path)
    p.add_argument("--previous-full-counts", type=Path)
    p.add_argument("--previous-coverage", type=Path)
    p.add_argument("--k", required=True, type=int)
    p.add_argument("--previous-tag", default="none")
    p.add_argument("--current-tag", required=True)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()

    if args.k < 1:
        raise SystemExit("k must be >= 1")

    args.out.mkdir(parents=True, exist_ok=True)
    current_visible = load_visible(args.current_private, args.k)

    previous_k = None
    previous_visible = {}
    public_verifiable = True

    if args.previous_public and args.previous_public.exists():
        previous_k = parse_k_header(args.previous_public)
        if args.previous_private and args.previous_private.exists():
            previous_visible = load_visible(args.previous_private, args.k)
            if args.k >= previous_k:
                public_previous = rethreshold_public(args.previous_public, args.k)
                if public_previous != previous_visible:
                    raise SystemExit("private previous counts disagree with re-thresholded public snapshot")
            else:
                public_verifiable = False
        else:
            if args.k < previous_k:
                raise SystemExit("lowering k requires the previous private count file")
            previous_visible = rethreshold_public(args.previous_public, args.k)
    elif args.previous_tag != "none":
        raise SystemExit("previous tag supplied without previous public snapshot")

    current_snapshot = args.out / "nameservers.txt"
    write_public_snapshot(current_snapshot, current_visible, args.k, args.current_tag)

    has_previous = args.previous_public is not None and args.previous_public.exists()
    if has_previous:
        changes, crossings = build_diff(previous_visible, current_visible, args.k)
    else:
        changes, crossings = [], []

    previous_k_text = str(previous_k) if previous_k is not None else "none"
    k_changed = previous_k is not None and previous_k != args.k

    previous_coverage = load_coverage(args.previous_coverage)
    current_coverage = load_coverage(args.current_coverage)
    coverage_changed = bool(previous_coverage) and previous_coverage != current_coverage
    comparison_break = coverage_changed or (previous_k is not None and args.k < previous_k)

    diff_path = args.out / "delegation-changes.txt"
    with open(diff_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# k={args.k}\n")
        fh.write(f"# previous_k={previous_k_text}\n")
        fh.write(f"# k_changed={bool_text(k_changed)}\n")
        fh.write(f"# coverage_changed={bool_text(coverage_changed)}\n")
        fh.write(f"# comparison_break={bool_text(comparison_break)}\n")
        fh.write(f"# public_verifiable={bool_text(public_verifiable)}\n")
        fh.write(f"# previous={args.previous_tag}\n")
        fh.write(f"# current={args.current_tag}\n")
        fh.write("# format=nameserver|previous|current|delta\n")
        for row in changes:
            fh.write("|".join(row) + "\n")
    write_gzip_copy(diff_path)

    ns_changes_path = args.out / "nameserver-changes.txt"
    with open(ns_changes_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# k={args.k}\n")
        fh.write(f"# previous={args.previous_tag}\n")
        fh.write(f"# current={args.current_tag}\n")
        fh.write("# format=operation|nameserver\n")
        for op, name in crossings:
            fh.write(f"{op}|{name}\n")
    write_gzip_copy(ns_changes_path)

    shutil.copyfile(args.current_coverage, args.out / "coverage.txt")

    current_full = load_key_values(args.current_full_counts)
    previous_full = load_key_values(args.previous_full_counts)
    counts_path = args.out / "counts.txt"
    with open(counts_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"k={args.k}\n")
        for key in sorted(current_full):
            fh.write(f"{key}={current_full[key]}\n")
        fh.write(f"nameservers_published={len(current_visible)}\n")
        total = int(current_full.get("nameservers_total", "0"))
        fh.write(f"nameservers_suppressed={max(0, total - len(current_visible))}\n")

    def int_or_none(values, key):
        try:
            return int(values[key])
        except (KeyError, ValueError):
            return None

    prev_edges = int_or_none(previous_full, "delegation_edges")
    cur_edges = int_or_none(current_full, "delegation_edges")
    edge_delta = cur_edges - prev_edges if prev_edges is not None and cur_edges is not None else None

    changed_exact = sum(1 for _, prev, cur, delta in changes if delta != "NA")
    entered = sum(1 for op, _ in crossings if op == "+")
    left = sum(1 for op, _ in crossings if op == "-")

    cc_path = args.out / "changes-counts.txt"
    with open(cc_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"k={args.k}\n")
        fh.write(f"previous_k={previous_k_text}\n")
        fh.write(f"k_changed={bool_text(k_changed)}\n")
        fh.write(f"coverage_changed={bool_text(coverage_changed)}\n")
        fh.write(f"comparison_break={bool_text(comparison_break)}\n")
        fh.write(f"public_verifiable={bool_text(public_verifiable)}\n")
        fh.write(f"nameservers_entered_visibility={entered}\n")
        fh.write(f"nameservers_left_visibility={left}\n")
        fh.write(f"nameservers_visible_changed={len(changes)}\n")
        fh.write(f"nameservers_visible_exact_count_changed={changed_exact}\n")
        fh.write(f"delegation_edges_previous={prev_edges if prev_edges is not None else 'NA'}\n")
        fh.write(f"delegation_edges_current={cur_edges if cur_edges is not None else 'NA'}\n")
        if edge_delta is None:
            fh.write("delegation_edges_delta=NA\n")
        else:
            fh.write(f"delegation_edges_delta={edge_delta:+d}\n")


if __name__ == "__main__":
    main()
