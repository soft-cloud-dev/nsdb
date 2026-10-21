#!/usr/bin/env python3
import argparse
import collections
import gzip
import io
import json
import sqlite3
import tarfile
from pathlib import Path


def normalize_name(value: str) -> str:
    name = value.strip().lower().rstrip(".")
    try:
        name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"non-ASCII DNS name; expected A-label form: {value!r}") from exc
    return name


def load_special_zones(path: Path) -> tuple[str, ...]:
    zones = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            zones.append(normalize_name(line.split("|", 1)[0]))
    return tuple(sorted(set(zones)))


def in_special_zone(name: str, zones: tuple[str, ...]) -> bool:
    return any(name == zone or name.endswith("." + zone) for zone in zones)


def soa_serial(rdata: str):
    fields = rdata.split()
    if len(fields) < 3:
        return "NA"
    try:
        return str(int(fields[2]))
    except ValueError:
        return "NA"


class Aggregate:
    def __init__(self, db_path: Path, flush_unique: int = 100000):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=OFF")
        self.conn.execute("PRAGMA synchronous=OFF")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.execute("CREATE TABLE ns_counts (nameserver TEXT PRIMARY KEY, delegations INTEGER NOT NULL)")
        self.batch = collections.Counter()
        self.flush_unique = flush_unique

    def add(self, nameserver: str):
        self.batch[nameserver] += 1
        if len(self.batch) >= self.flush_unique:
            self.flush()

    def flush(self):
        if not self.batch:
            return
        self.conn.executemany(
            "INSERT INTO ns_counts(nameserver, delegations) VALUES (?, ?) "
            "ON CONFLICT(nameserver) DO UPDATE SET delegations=delegations+excluded.delegations",
            self.batch.items(),
        )
        self.conn.commit()
        self.batch.clear()

    def stats(self):
        self.flush()
        row = self.conn.execute("SELECT COUNT(*), COALESCE(SUM(delegations), 0) FROM ns_counts").fetchone()
        return int(row[0]), int(row[1])

    def write(self, path: Path):
        self.flush()
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("# format=nameserver|delegations\n")
            for name, count in self.conn.execute(
                "SELECT nameserver, delegations FROM ns_counts ORDER BY nameserver"
            ):
                fh.write(f"{name}|{count}\n")

    def close(self):
        self.conn.close()


def process_zone_stream(stream, label: str, special_zones: tuple[str, ...], aggregate: Aggregate):
    records = 0
    apex = None
    first_soa_serial = "NA"
    saw_final_soa = False
    delegated_started = False
    current_owner = None
    current_targets = set()
    previous_owner = None
    delegated_names = 0
    delegation_edges = 0
    excluded_owners = 0
    excluded_targets = 0

    def flush_owner():
        nonlocal current_owner, current_targets, delegated_names, delegation_edges, excluded_owners, excluded_targets
        if current_owner is None or not current_targets:
            current_owner = None
            current_targets = set()
            return
        if in_special_zone(current_owner, special_zones):
            excluded_owners += 1
            current_owner = None
            current_targets = set()
            return
        retained = []
        for target in current_targets:
            if in_special_zone(target, special_zones):
                excluded_targets += 1
            else:
                retained.append(target)
        if retained:
            delegated_names += 1
            delegation_edges += len(retained)
            for target in retained:
                aggregate.add(target)
        current_owner = None
        current_targets = set()

    for raw in stream:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        line = raw.rstrip("\r\n")
        if not line:
            raise ValueError(f"{label}: blank line violates CZDS zone format")
        fields = line.split("\t", 4)
        if len(fields) != 5:
            raise ValueError(f"{label}: expected five tab-separated fields at record {records + 1}")
        owner_raw, ttl, rrclass, rrtype, rdata = fields
        owner = normalize_name(owner_raw)
        rrclass = rrclass.lower()
        rrtype = rrtype.lower()
        records += 1

        if records == 1:
            if rrtype != "soa":
                raise ValueError(f"{label}: first record is not SOA")
            apex = owner
            first_soa_serial = soa_serial(rdata)
            continue

        if owner == apex and rrtype == "soa":
            flush_owner()
            saw_final_soa = True
            continue

        if saw_final_soa:
            raise ValueError(f"{label}: records appear after final SOA")

        if owner == apex:
            if delegated_started:
                raise ValueError(f"{label}: apex record found after delegated records started")
            continue

        delegated_started = True
        if previous_owner is not None and owner < previous_owner:
            raise ValueError(f"{label}: records are not ordered by owner: {owner} after {previous_owner}")
        previous_owner = owner

        if current_owner != owner:
            flush_owner()
            current_owner = owner

        if rrclass == "in" and rrtype == "ns":
            parts = rdata.split()
            if not parts:
                raise ValueError(f"{label}: empty NS target for {owner}")
            target = normalize_name(parts[0])
            if not target:
                raise ValueError(f"{label}: root/empty NS target for {owner}")
            current_targets.add(target)

    flush_owner()

    if apex is None:
        raise ValueError(f"{label}: empty zone")
    if not saw_final_soa:
        raise ValueError(f"{label}: final SOA missing")

    return {
        "zone": apex,
        "soa_serial": first_soa_serial,
        "records": records,
        "delegated_names": delegated_names,
        "delegation_edges": delegation_edges,
        "locally_served_owners_excluded": excluded_owners,
        "locally_served_ns_targets_excluded": excluded_targets,
    }


def open_text_stream(path: Path):
    with open(path, "rb") as fh:
        magic = fh.read(2)
    if magic == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return open(path, "rt", encoding="utf-8", newline="")


def process_input(path: Path, special_zones, aggregate):
    rows = []
    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as tar:
            members = [m for m in tar.getmembers() if m.isfile()]
            if not members:
                raise ValueError(f"{path}: tar contains no zone files")
            for member in sorted(members, key=lambda m: m.name):
                raw = tar.extractfile(member)
                if raw is None:
                    raise ValueError(f"{path}: cannot read {member.name}")
                with io.TextIOWrapper(raw, encoding="utf-8", newline="") as text:
                    rows.append(process_zone_stream(text, f"{path.name}:{member.name}", special_zones, aggregate))
    else:
        with open_text_stream(path) as text:
            rows.append(process_zone_stream(text, path.name, special_zones, aggregate))
    return rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--zones-dir", required=True, type=Path)
    p.add_argument("--special-zones", required=True, type=Path)
    p.add_argument("--private-counts", required=True, type=Path)
    p.add_argument("--coverage", required=True, type=Path)
    p.add_argument("--counts", required=True, type=Path)
    args = p.parse_args()

    manifest_path = args.zones_dir / "manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"missing {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = [args.zones_dir / item["filename"] for item in manifest.get("files", [])]
    if not files:
        raise SystemExit("zone manifest is empty")

    for path in files:
        if not path.is_file():
            raise SystemExit(f"zone file missing: {path}")

    args.private_counts.parent.mkdir(parents=True, exist_ok=True)
    args.coverage.parent.mkdir(parents=True, exist_ok=True)
    args.counts.parent.mkdir(parents=True, exist_ok=True)

    special_zones = load_special_zones(args.special_zones)
    db_path = args.private_counts.with_suffix(".sqlite")
    if db_path.exists():
        db_path.unlink()
    aggregate = Aggregate(db_path)
    coverage = []

    try:
        for path in sorted(files):
            coverage.extend(process_input(path, special_zones, aggregate))
        aggregate.write(args.private_counts)
        nameservers_total, delegation_edges = aggregate.stats()
    finally:
        aggregate.close()
        if db_path.exists():
            db_path.unlink()

    coverage.sort(key=lambda row: row["zone"])
    if len({row["zone"] for row in coverage}) != len(coverage):
        raise SystemExit("duplicate zone apex detected across CZDS inputs")

    delegated_names = sum(row["delegated_names"] for row in coverage)
    excluded_owners = sum(row["locally_served_owners_excluded"] for row in coverage)
    excluded_targets = sum(row["locally_served_ns_targets_excluded"] for row in coverage)
    edges_from_coverage = sum(row["delegation_edges"] for row in coverage)
    if delegation_edges != edges_from_coverage:
        raise SystemExit("aggregate delegation edge count does not match coverage totals")

    with open(args.coverage, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# format=zone|soa_serial|records|delegated_names|delegation_edges\n")
        for row in coverage:
            fh.write(
                f"{row['zone']}|{row['soa_serial']}|{row['records']}|"
                f"{row['delegated_names']}|{row['delegation_edges']}\n"
            )

    with open(args.counts, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"zones={len(coverage)}\n")
        fh.write(f"delegated_names={delegated_names}\n")
        fh.write(f"delegation_edges={delegation_edges}\n")
        fh.write(f"nameservers_total={nameservers_total}\n")
        fh.write(f"locally_served_owners_excluded={excluded_owners}\n")
        fh.write(f"locally_served_ns_targets_excluded={excluded_targets}\n")


if __name__ == "__main__":
    main()
