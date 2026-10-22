#!/usr/bin/env python3
import argparse
import collections
import gzip
import io
import json
import sqlite3
import tarfile
from pathlib import Path


# These fixed codes may appear in public CI logs; exception messages may not.
_PUBLIC_VALIDATION_CODES = frozenset(["dns_name_non_ascii","dns_escape_dangling","dns_escape_decimal_range","dns_label_empty","dns_label_too_long","dns_name_too_long","dns_label_non_ascii","ns_target_empty","ns_rdata_extra","ns_target_escape_dangling","ns_target_root","record_blank","record_fields","header_record_fields","apex_hint_missing","apex_hint_unavailable","after_final_soa","soa_owner_class","soa_serial_invalid","soa_serial_mismatch","soa_excess","ns_owner_outside_apex","ns_owner_order","zone_empty","soa_missing","soa_final_missing","archive_empty","archive_member_unreadable","record_fields_comment","record_fields_directive","record_fields_space_delimited","record_fields_missing_tabs","record_fields_partial_tabs"])


def classify_record_fields(line: str) -> str:
    """Classify format violations without disclosing record content or offsets."""
    if not line:
        return "record_blank"
    leading = line.lstrip()
    if leading.startswith(";"):
        return "record_fields_comment"
    if leading.startswith("$"):
        return "record_fields_directive"
    if "\t" in line:
        return "record_fields_partial_tabs"
    if any(char.isspace() for char in line):
        return "record_fields_space_delimited"
    return "record_fields_missing_tabs"

class ZoneValidationError(ValueError):
    """Detailed errors remain private; a fixed code identifies the invariant."""

    def __init__(self, code: str, detail: str):
        if code not in _PUBLIC_VALIDATION_CODES:
            raise ValueError("unknown validation code")
        super().__init__(detail)
        self.code = code


def public_validation_code(exc: BaseException) -> str:
    """Never use exception text or zone-record data in public diagnostics."""
    if isinstance(exc, ZoneValidationError) and exc.code in _PUBLIC_VALIDATION_CODES:
        return exc.code
    if isinstance(exc, UnicodeError):
        return "input_encoding"
    if isinstance(exc, EOFError):
        return "input_truncated"
    if isinstance(exc, OSError):
        return "input_io"
    if isinstance(exc, tarfile.TarError):
        return "archive_error"
    return "unclassified_error"


def _parse_master_name(value: str) -> list[bytes]:
    source = value.strip()
    try:
        source.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ZoneValidationError("dns_name_non_ascii", f"non-ASCII DNS name; expected A-label/master-file form: {value!r}") from exc

    if source == ".":
        return []

    labels: list[bytearray] = [bytearray()]
    index = 0
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 1
            if index >= len(source):
                raise ZoneValidationError("dns_escape_dangling", f"dangling DNS master-file escape: {value!r}")
            if (
                index + 2 < len(source)
                and source[index : index + 3].isdigit()
            ):
                octet = int(source[index : index + 3], 10)
                if octet > 255:
                    raise ZoneValidationError("dns_escape_decimal_range", f"DNS decimal escape exceeds 255: {value!r}")
                labels[-1].append(octet)
                index += 3
                continue
            labels[-1].append(ord(source[index]))
            index += 1
            continue

        if char == ".":
            if index == len(source) - 1:
                index += 1
                break
            if not labels[-1]:
                raise ZoneValidationError("dns_label_empty", f"empty DNS label: {value!r}")
            labels.append(bytearray())
            index += 1
            continue

        labels[-1].append(ord(char))
        index += 1

    if labels and not labels[-1]:
        raise ZoneValidationError("dns_label_empty", f"empty DNS label: {value!r}")

    result = [bytes(label) for label in labels]
    for label in result:
        if len(label) > 63:
            raise ZoneValidationError("dns_label_too_long", f"DNS label exceeds 63 octets: {value!r}")

    wire_length = 1 + sum(1 + len(label) for label in result)
    if wire_length > 255:
        raise ZoneValidationError("dns_name_too_long", f"DNS name exceeds 255 wire octets: {value!r}")

    return result


def _canonical_label(label: bytes, original: str) -> str:
    if any(octet >= 128 for octet in label):
        raise ZoneValidationError("dns_label_non_ascii", f"non-ASCII DNS label; expected A-label form: {original!r}")

    lowered = bytes(
        octet + 32 if 65 <= octet <= 90 else octet
        for octet in label
    )

    # DNS label comparison is ASCII case-insensitive (RFC 4343).
    # An xn-- prefix does not require a DNS name, particularly an NS
    # target, to pass Python's legacy IDNA2003 Unicode round-trip.
    # Preserve the exact lowercased ASCII DNS label without decoding it.

    safe = bytearray(b"abcdefghijklmnopqrstuvwxyz0123456789-_")
    output = []
    for octet in lowered:
        if octet in safe:
            output.append(chr(octet))
        else:
            output.append(f"\\{octet:03d}")
    return "".join(output)


def normalize_name(value: str) -> str:
    labels = _parse_master_name(value)
    return ".".join(_canonical_label(label, value) for label in labels)


def dns_canonical_owner_key(value: str) -> tuple[bytes, ...]:
    """RFC 4034 section 6.1: compare wire labels from right to left.

    Compare raw label octets, not dotted strings, to preserve the ordering
    of escaped dots and escaped decimal octets. ASCII case is insignificant.
    """
    return tuple(
        bytes(octet + 32 if 65 <= octet <= 90 else octet for octet in label)
        for label in reversed(_parse_master_name(value))
    )


def parse_single_name_rdata(rdata: str, label: str, owner: str) -> str:
    source = rdata.strip()
    if not source:
        raise ZoneValidationError("ns_target_empty", f"{label}: empty NS target for {owner}")

    escaped = False
    index = 0
    while index < len(source):
        char = source[index]
        if escaped:
            if char.isdigit() and index + 2 < len(source) and source[index : index + 3].isdigit():
                index += 3
            else:
                index += 1
            escaped = False
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if char.isspace():
            if source[index:].strip():
                raise ZoneValidationError("ns_rdata_extra", f"{label}: NS record has extra RDATA fields for {owner}")
            source = source[:index]
            break
        index += 1

    if escaped:
        raise ZoneValidationError("ns_target_escape_dangling", f"{label}: dangling escape in NS target for {owner}")

    target = normalize_name(source)
    if not target:
        raise ZoneValidationError("ns_target_root", f"{label}: root/empty NS target for {owner}")
    return target


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


def infer_apex_from_filename(filename: str) -> str | None:
    """Use the CZDS zone filename as a trusted apex hint when SOA is not first.

    The common CZDS formats are <tld>.txt.gz and <tld>.zone.gz.
    A filename without a recognized zone suffix is not an apex hint.
    """
    basename = Path(filename).name
    for suffix in (".txt.gz", ".zone.gz", ".txt", ".zone"):
        if basename.lower().endswith(suffix):
            candidate = basename[: -len(suffix)]
            if candidate:
                return normalize_name(candidate)
            break
    return None


def process_zone_stream(
    stream,
    label: str,
    special_zones: tuple[str, ...],
    aggregate: Aggregate,
    expected_apex: str | None = None,
):
    records = 0
    apex_hint = normalize_name(expected_apex) if expected_apex is not None else None
    apex = None
    first_soa_serial = "NA"
    soa_count = 0
    saw_final_soa = False
    last_record_is_soa = False
    current_owner = None
    current_targets = set()
    previous_owner = None
    previous_owner_canonical_key = None
    plain_order_possible = True
    canonical_order_possible = True
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
            raise ZoneValidationError("record_blank", f"{label}: blank line violates CZDS zone format")
        fields = line.split("\t", 4)
        if len(fields) != 5:
            raise ZoneValidationError(classify_record_fields(line), f"{label}: expected five tab-separated fields at record {records + 1}")
        owner_raw, ttl, rrclass, rrtype, rdata = fields
        owner = normalize_name(owner_raw)
        rrclass = rrclass.lower()
        rrtype = rrtype.lower()
        records += 1

        if records == 1:
            if rrclass == "in" and rrtype == "soa":
                # The SOA owner is authoritative when a standard header
                # exists; the filename hint is only a fallback.
                apex = owner
            elif apex_hint is not None:
                apex = apex_hint
            else:
                raise ZoneValidationError(
                    "apex_hint_missing",
                    f"{label}: first record is not SOA and zone apex cannot be inferred"
                )

        if saw_final_soa:
            raise ZoneValidationError("after_final_soa", f"{label}: records appear after final SOA")

        if rrtype == "soa":
            if owner != apex or rrclass != "in":
                raise ZoneValidationError("soa_owner_class", f"{label}: SOA owner/class conflicts with zone apex {apex}")
            serial = soa_serial(rdata)
            if serial == "NA":
                raise ZoneValidationError("soa_serial_invalid", f"{label}: invalid apex SOA serial")
            if soa_count and serial != first_soa_serial:
                raise ZoneValidationError(
                    "soa_serial_mismatch",
                    f"{label}: mismatched apex SOA serials: {first_soa_serial} versus {serial}"
                )
            soa_count += 1
            if soa_count > 2:
                raise ZoneValidationError("soa_excess", f"{label}: more than two SOA records")
            first_soa_serial = serial
            last_record_is_soa = True
            if soa_count == 2:
                # A second SOA is the duplicated closing record.
                flush_owner()
                saw_final_soa = True
            continue

        last_record_is_soa = False

        if owner == apex:
            # CZDS exports may place apex metadata anywhere after the
            # first SOA. Apex NS records are not child delegations.
            continue

        if rrclass != "in" or rrtype != "ns":
            # Glue and DNSSEC records do not advance delegation-owner
            # grouping or ordering. An unrelated A/AAAA/RRSIG owner may
            # appear between NS records for the same delegation.
            continue

        if not owner.endswith("." + apex):
            raise ZoneValidationError("ns_owner_outside_apex", f"{label}: NS delegation owner outside zone {apex}: {owner}")

        if current_owner != owner:
            canonical_key = dns_canonical_owner_key(owner_raw)
            if previous_owner is not None:
                # ICANN specifies alphabetical records, but real CZDS
                # exports use more than one DNS name ordering convention.
                # Accept a zone only while *one entire* delegation stream
                # remains consistently ordered. Returning to an earlier
                # delegation owner is impossible in either sorted order,
                # preventing double counts.
                if owner < previous_owner:
                    plain_order_possible = False
                if canonical_key < previous_owner_canonical_key:
                    canonical_order_possible = False
                if not (plain_order_possible or canonical_order_possible):
                    raise ZoneValidationError(
                        "ns_owner_order",
                        f"{label}: NS delegation owners violate both plain and DNS "
                        f"canonical ordering: {owner} after {previous_owner}"
                    )
            flush_owner()
            current_owner = owner
            previous_owner = owner
            previous_owner_canonical_key = canonical_key

        current_targets.add(parse_single_name_rdata(rdata, label, owner))

    flush_owner()

    if apex is None:
        raise ZoneValidationError("zone_empty", f"{label}: empty zone")
    if soa_count == 0:
        raise ZoneValidationError("soa_missing", f"{label}: no valid apex SOA found")
    if not last_record_is_soa:
        raise ZoneValidationError("soa_final_missing", f"{label}: final SOA missing")

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
                raise ZoneValidationError("archive_empty", f"{path}: tar contains no zone files")
            for member in sorted(members, key=lambda m: m.name):
                raw = tar.extractfile(member)
                if raw is None:
                    raise ZoneValidationError("archive_member_unreadable", f"{path}: cannot read {member.name}")
                with io.TextIOWrapper(raw, encoding="utf-8", newline="") as text:
                    rows.append(
                        process_zone_stream(
                            text, f"{path.name}:{member.name}", special_zones,
                            aggregate, expected_apex=infer_apex_from_filename(member.name),
                        )
                    )
    else:
        with open_text_stream(path) as text:
            rows.append(
                process_zone_stream(
                    text, path.name, special_zones, aggregate,
                    expected_apex=infer_apex_from_filename(path.name),
                )
            )
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
    try:
        main()
    except Exception as exc:
        # GitHub Actions logs are public and exception text may contain licensed RDATA.
        raise SystemExit(
            f"NSDB aggregation failed (reason={public_validation_code(exc)})"
        ) from None
