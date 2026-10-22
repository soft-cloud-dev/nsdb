# nsdb

Daily nameserver delegation statistics derived from ICANN Centralized Zone Data Service (CZDS) zone files, with thresholded public snapshots and reproducible semantic diffs.

`nsdb` publishes aggregate nameserver counts. It does **not** publish CZDS zone files or domain-to-nameserver mappings.

## License status

No open-source or aggregate-data license has been granted yet. Public repository visibility does not itself grant reuse rights. The maintainer decision is tracked in [issue #1](https://github.com/soft-cloud-dev/nsdb/issues/1); code and data-artifact licensing must be chosen explicitly and documented separately if their terms differ.

## Public data model

Let `count_day(n)` be the number of unique delegated DNS names whose NS RRset references nameserver `n` on a given build day.

For publication threshold `k`:

```text
visible(n, day) := count_day(n) >= k
```

Only visible nameservers are written to the public snapshot. Every exact nameserver count that appears in a public artifact is therefore at least `k`. When a diff must represent a hidden side, it uses the literal `<k` rather than the hidden integer.

The current threshold is stored in [`config/k.txt`](config/k.txt). The initial value is `5`; it should be reviewed against the empirical delegation-count distribution rather than treated as a permanent privacy constant.

## Sources

The build uses:

- ICANN CZDS API for approved gTLD zone files: `https://czds.icann.org/`
- ICANN reference API clients: `https://github.com/icann/czds-api-client-python`
- IANA Locally-Served DNS Zones: `https://www.iana.org/assignments/locally-served-dns-zones/locally-served-dns-zones.txt`

The normalized IANA exclusion registry used by releases is pinned in [`config/locally-served-dns-zones.txt`](config/locally-served-dns-zones.txt). Daily releases never change exclusion semantics by fetching IANA live. A separate weekly workflow regenerates the normalized file and opens or updates a pull request only when the authoritative registry changes, so semantic changes are reviewed before merge.

CZDS access is authenticated and subject to the terms accepted for each registry/TLD. ICANN documents that the applicable zone-file agreement can differ by registry agreement generation and that users accept registry-operator terms for each TLD request. Current standard CZDS terms prohibit redistribution of the raw zone data except when incorporated into a qualifying value-added product or service, require reasonable protection against unauthorized access/use/disclosure, and limit access to a zone file to no more than once per 24-hour period. `nsdb` therefore keeps raw zone data outside this repository on a protected self-hosted runner and never uploads raw zones or domain-to-nameserver mappings as release artifacts.

This repository does not claim that the publication threshold by itself establishes legal compliance for every TLD. The operator remains responsible for the exact terms accepted for every CZDS zone used by a build.

## Delegation counting

CZDS zone files use the standardized master-file subformat defined by ICANN: one complete record per line, fully qualified names, and records ordered alphabetically except for the duplicated SOA record.

For each zone, the build:

1. validates the zone apex and SOA record(s), including the final SOA; when an SOA is not the first record, it uses the trusted CZDS filename as the apex hint and still fails closed if the SOA is missing or inconsistent;
2. validates record ordering needed for streaming owner-group processing;
3. parses RFC 1035 master-file escapes, validates DNS wire-length limits, validates `xn--` A-labels, canonicalizes owner names and NS targets to lowercase ASCII representation, and removes the trailing root dot;
4. ignores apex NS records because they describe the TLD itself rather than child delegations;
5. groups NS records by delegation owner;
6. deduplicates nameserver targets inside each owner RRset after canonicalization;
7. rejects empty/root NS targets and non-ASCII U-label input rather than silently transforming it;
8. excludes delegation owners and nameserver targets under IANA locally-served zones using DNS-label-aware suffix matching;
9. increments each retained nameserver once per unique delegated owner;
10. merges per-zone counts into a disk-backed SQLite aggregate.

The exact aggregate is private build state. Publication thresholding happens only after aggregation.

## Public snapshot

`nameservers.txt` contains only visible nameservers:

```text
# k=5
# snapshot=nsdb-2026-10-21
# format=nameserver|delegations
ns1.example.net|417
ns2.example.net|286
```

Absence means only:

```text
count < k
```

It must not be interpreted as `count = 0`.

## Diff 1: nameserver visibility changes

`nameserver-changes.txt` records threshold crossings:

```text
# k=5
# previous=nsdb-2026-10-20
# current=nsdb-2026-10-21
# format=operation|nameserver
+|ns3.new-provider.net
-|ns9.old-provider.net
```

Semantics:

```text
+ iff previous < k <= current
- iff current < k <= previous
```

This file has no independent information. It is exactly the projection of Diff 2 rows containing `<k`.

## Diff 2: delegation-count changes

`delegation-changes.txt` emits a row iff the public value changed and at least one side is visible:

```text
# k=5
# previous=nsdb-2026-10-20
# current=nsdb-2026-10-21
# format=nameserver|previous|current|delta
ns1.cloudflare.com|892341|893102|+761
ns3.new-provider.net|<5|286|NA
ns9.old-provider.net|7|<5|NA
```

Rules:

- both sides `>= k`: publish exact values and exact delta;
- one side `< k`: publish `<k` and set `delta=NA`;
- both sides `< k`: publish nothing.

The redaction is intentional. Publishing `3|5|+2`, for example, would disclose a count that the previous public snapshot intentionally hid.

## Verification invariants

For an unchanged threshold, both diffs are pure functions of the two public snapshots. Raising `k` is also publicly verifiable because the previous public snapshot can be re-thresholded upward.

CI asserts:

1. every value in `nameservers.txt` is `>= k`;
2. Diff 2 contains no exact integer below `k`;
3. a Diff 2 row containing `<k` always has `delta=NA`;
4. a row with two exact values has the exact arithmetic delta;
5. Diff 2 is reconstructible from the two public snapshots whenever `public_verifiable=true`;
6. Diff 1 is exactly the threshold-crossing projection of Diff 2;
7. nameservers hidden on both days never appear in either diff;
8. serialization and gzip output are deterministic.

The independent verifier is [`scripts/verify_public.py`](scripts/verify_public.py).

## Changing `k`

Every snapshot and diff includes `k` metadata.

If `k` is raised, the comparison evaluates both days using the new threshold. This remains publicly verifiable because all newly hidden rows were present in the previous snapshot with exact values.

If `k` is lowered, yesterday's public snapshot does not contain nameservers that were below the old threshold but above the new one. The build therefore **does not** use yesterday's private exact count to fill that gap, because doing so would retroactively disclose a value hidden by the old publication contract.

Instead, the previous side remains expressed at the old threshold. For example, lowering from `10` to `5` may produce:

```text
# previous_k=10
# k=5
# comparison_mode=k-lowered
ns.example|<10|8|NA
```

It must never produce `ns.example|7|8|+1` if the value `7` was not public yesterday.

Such a release is marked:

```text
k_changed=true
comparison_mode=k-lowered
comparison_break=true
public_verifiable=false
```

Lowering `k` is therefore treated as a comparison-boundary event similar to a coverage change. Rows still describe the transition between the two public visibility contracts, but they must not be interpreted as a same-threshold day-over-day measurement.

No hysteresis is used. Visibility depends only on `(count, k)` for that day, so nameservers near the threshold may legitimately oscillate between visible and hidden states.

## Coverage changes

`coverage.txt` publishes the zones included in the build:

```text
# format=zone|soa_serial|records|delegated_names|delegation_edges
example|2026102101|123456|42000|102000
```

If the set of zones changes between releases, the diffs are marked:

```text
coverage_changed=true
comparison_break=true
```

This distinguishes nameserver movement from changes caused by CZDS access or source coverage.

## Aggregate counts

`counts.txt` is calculated from the complete private aggregate, then augmented with public visibility counts:

```text
k=5
zones=...
delegated_names=...
delegation_edges=...
nameservers_total=...
nameservers_published=...
nameservers_suppressed=...
```

`changes-counts.txt` reports full-dataset edge totals together with public visibility transitions. The sum of exact deltas in `delegation-changes.txt` is **not** expected to equal `delegation_edges_delta`: nameservers below `k` are intentionally absent or redacted, and net per-nameserver counts do not expose gross delegation churn.

## Release artifacts

Each daily release contains:

| Artifact | Description |
| --- | --- |
| `nameservers.txt` | Thresholded nameserver delegation snapshot |
| `nameservers.txt.gz` | Deterministic gzip snapshot |
| `delegation-changes.txt` | Threshold-aware delegation count diff |
| `delegation-changes.txt.gz` | Compressed Diff 2 |
| `nameserver-changes.txt` | Threshold crossings, derived from Diff 2 |
| `nameserver-changes.txt.gz` | Compressed Diff 1 |
| `coverage.txt` | Zone coverage and source statistics |
| `special-zones.txt` | Normalized IANA locally-served exclusion set used by the build |
| `counts.txt` | Full aggregate statistics plus publication counts |
| `changes-counts.txt` | Full aggregate change totals and public threshold transitions |
| `SHA256SUMS` | SHA-256 checksums for all published artifacts |

The release workflow also creates a GitHub Artifact Attestation for the complete `dist/*` payload using the immutable commit currently corresponding to `actions/attest@v4`. This binds each released file digest to the official GitHub Actions workflow through signed SLSA provenance. Downstream users can verify an artifact with the GitHub CLI:

```sh
gh attestation verify nameservers.txt.gz --repo soft-cloud-dev/nsdb
```

Release tags use:

```text
nsdb-YYYY-MM-DD
```

## Daily workflow

The GitHub Actions workflow runs at `07:17 UTC` and requires a persistent self-hosted runner carrying the label `nsdb`.

A persistent runner is deliberate:

- CZDS data can be large;
- authenticated zone files must not be exposed as public workflow artifacts;
- same-day workflow reruns must reuse already downloaded zone files instead of downloading them a second time;
- retained private aggregates support auditing, threshold-distribution analysis, and reproducible rebuilds without changing the public disclosure contract.

Configure repository secrets:

```text
ICANN_USERNAME
ICANN_PASSWORD
```

Optionally configure repository variable:

```text
NSDB_STATE_DIR
```

It defaults to:

```text
/var/lib/nsdb
```

The state directory must be accessible only to the runner account.

The workflow performs:

```text
pinned IANA locally-served zones
        +
ICANN CZDS zone files
        |
        v
validate and stream NS delegations
        |
        v
private exact nameserver counts
        |
        +--> full aggregate counts
        |
        v
apply publication threshold k
        |
        +--> nameservers.txt
        |
previous release + previous private state
        |
        +--> delegation-changes.txt
        +--> nameserver-changes.txt
        |
        v
independent public verification
        |
        v
SHA256SUMS + GitHub Release
```

## Preflight for non-leading SOA zones

Legacy and nonstandard CZDS archives can begin with apex NS or other records rather than SOA. The build accepts such input only if the file has a recognizable CZDS zone filename and a valid apex SOA at the end (or a matching earlier SOA plus the closing copy). A missing SOA, mismatched SOA serial, wrong SOA owner, or out-of-zone NS delegation still fails the build.

Before the expensive full aggregation, `scripts/preflight_czds.py` reads each archive's first record and **fully validates only files without a leading SOA**, using a discard-only nameserver sink. This avoids a multi-hour rebuild failing late on another non-leading SOA format issue. It emits file names and pass/fail status only, not licensed domain-to-nameserver relationships.

On the protected self-hosted runner, the exceptional-zone preflight can also be run independently against the already downloaded CZDS dataset:

```sh
python scripts/preflight_czds.py \
  --zones-dir "$NSDB_STATE_DIR/zones/2026-10-21" \
  --special-zones config/locally-served-dns-zones.txt
```

Normal first-SOA archives are not fully re-parsed during this preflight. A passing preflight therefore does **not** certify the entire CZDS dataset, and the full build remains mandatory. The current aggregation uses an ephemeral global SQLite database, so a failed run reprocesses earlier zones; per-zone private checkpoints are a separate future reliability improvement.

## Same-day reruns

`scripts/fetch_czds.py` writes a persistent per-day manifest. If that day's download set is complete, a rerun reuses it without contacting the zone-download endpoints again.

If a `.part` file exists, the fetcher fails closed rather than automatically retrying an ambiguous partial transfer that may already have consumed the permitted download for that 24-hour period.

Old raw zone directories are pruned only after successful publication. Private aggregate count files are retained.

## Running the transformation locally

Given an already downloaded CZDS directory with the generated `manifest.json`:

```sh
python3 scripts/build_nsdb.py --zones-dir state/zones/2026-10-21 --special-zones config/locally-served-dns-zones.txt --private-counts private/2026-10-21/nameserver-counts.txt --coverage private/2026-10-21/coverage.txt --counts private/2026-10-21/counts.txt
python3 scripts/publish_nsdb.py --current-private private/2026-10-21/nameserver-counts.txt --current-full-counts private/2026-10-21/counts.txt --current-coverage private/2026-10-21/coverage.txt --k "$(cat config/k.txt)" --current-tag nsdb-2026-10-21 --out dist
```

To check whether IANA changed the authoritative locally-served registry without changing release semantics directly:

```sh
python3 scripts/fetch_special_zones.py --output /tmp/locally-served-dns-zones.txt
diff -u config/locally-served-dns-zones.txt /tmp/locally-served-dns-zones.txt
```

The scheduled `refresh-iana.yml` workflow automates that comparison and opens a pull request when the normalized registry changes.

For consecutive builds, pass the previous public snapshot, coverage, full counts, and retained private counts to `publish_nsdb.py`; the workflow shows the complete invocation.

## Privacy threat model

The threshold prevents direct publication of an individual nameserver count below `k`; it is **not** differential privacy and does not make visible nameservers anonymous.

A hard threshold also does not hide threshold-crossing information from an active observer. For example, an actor who independently knows that it controls `k-1` delegations to a nameserver and then adds one more can infer the prior count when that nameserver first becomes visible as `<k|k|NA`. This is inherent to stateless hard-threshold publication and is not prevented by redacting the hidden side. The redaction prevents the dataset itself from publishing the exact hidden value; it does not protect against external knowledge chosen or observed by an adversary.

The exact global totals in `counts.txt` and `changes-counts.txt` are computed over the complete private aggregate. Those totals can reveal aggregate movement in the suppressed tail. In unusually sparse change scenarios, external knowledge plus global totals may narrow the possible movement of one or more hidden nameservers.

This is an explicit trade-off in the current data contract: exact global totals are retained for measurement and auditability. Consumers must not interpret `k` as a formal reconstruction-resistance guarantee. If stronger privacy becomes a requirement, the global totals should be removed, coarsely bucketed, or released under a formally specified noise mechanism; changing that policy would be a versioned publication-contract change.

The IANA exclusion source used here is specifically the **Locally-Served DNS Zones** registry. It is not the complete IANA Special-Use Domain Names registry. Names such as `.local` or `.test` must not be silently added to this exclusion set unless an additional authoritative source and explicit policy are introduced.

## Performance model

Compressed CZDS inputs are parsed as streams and are not expanded to uncompressed copies on disk. Download progress is checkpointed after every successfully persisted zone file, so a later build retry reuses completed downloads and does not intentionally re-fetch them.

The aggregate database is a throwaway, single-writer SQLite database whose source zone files remain available for rebuild. The current `journal_mode=OFF` / `synchronous=OFF` choice favors sequential build speed over crash recovery of that temporary database. Switching to WAL, adding a large fixed cache, external merge-sort aggregation, or SOA-based per-zone reuse should be driven by benchmarks from the production CZDS workload rather than assumed to be faster.

SOA-based skip-unchanged processing requires retaining each zone's private nameserver contribution, not only its coverage row, so it is intentionally not implemented as a superficial serial check.

## Security and publication boundary

The repository intentionally excludes:

- raw CZDS zone files;
- domain-to-nameserver edges;
- nameserver counts below `k`;
- exact threshold-crossing deltas that would reveal hidden counts;
- ICANN credentials or access tokens;
- private per-day exact nameserver count files.

`k` limits disclosure of the long tail; it is not anonymization. A nameserver serving at least `k` delegated names is intentionally visible. Threshold selection should therefore be based on the observed private count distribution and the intended publication policy.
