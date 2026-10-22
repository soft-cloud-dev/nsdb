"""Subprocess-level checks for the preflight privacy and fast-failure gate."""
import gzip
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "preflight_czds.py"


class PreflightTests(unittest.TestCase):
    @staticmethod
    def invoke(directory: pathlib.Path, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--zones-dir",
                str(directory / "zones"),
                "--special-zones",
                str(directory / "special-zones.txt"),
                *extra,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    @staticmethod
    def invoke_build(directory: pathlib.Path, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "build_nsdb.py"),
                "--zones-dir",
                str(directory / "zones"),
                "--special-zones",
                str(directory / "special-zones.txt"),
                "--private-counts",
                str(directory / "private-counts.txt"),
                "--coverage",
                str(directory / "coverage.txt"),
                "--counts",
                str(directory / "counts.txt"),
                *extra,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    @staticmethod
    def setup_fixture(directory: pathlib.Path, filename: str, records: list[str]) -> None:
        zones = directory / "zones"
        zones.mkdir()
        (directory / "special-zones.txt").write_text("home.arpa\n", encoding="utf-8")
        (zones / "manifest.json").write_text(
            json.dumps({"files": [{"filename": filename}]}), encoding="utf-8"
        )
        with gzip.open(zones / filename, "wt", encoding="utf-8") as out:
            out.write("\n".join(records) + "\n")

    @staticmethod
    def setup_many(directory: pathlib.Path, by_filename: dict[str, list[str]]) -> None:
        zones = directory / "zones"
        zones.mkdir()
        (directory / "special-zones.txt").write_text("home.arpa\n", encoding="utf-8")
        (zones / "manifest.json").write_text(
            json.dumps({"files": [{"filename": name} for name in sorted(by_filename)]}),
            encoding="utf-8",
        )
        for filename, records in by_filename.items():
            with gzip.open(zones / filename, "wt", encoding="utf-8") as out:
                out.write("\n".join(records) + "\n")

    def test_temporary_gov_exclusion_is_exact_and_both_stages_match(self):
        gov = [
            "gov.\t3600\tIN\tNS\tns.gov.",
            "confidential.gov. 3600 IN NS ns.secret.example.",
            "gov.\t3600\tIN\tSOA\tns.gov. hostmaster.gov. 123 2 3 4 5",
        ]
        example = [
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 11 2 3 4 5",
            "child.example.\t3600\tIN\tNS\tns1.example.net.",
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 11 2 3 4 5",
        ]
        govuk = [
            "govuk.\t3600\tIN\tSOA\tns.govuk. hostmaster.govuk. 12 2 3 4 5",
            "child.govuk.\t3600\tIN\tNS\tns2.example.net.",
            "govuk.\t3600\tIN\tSOA\tns.govuk. hostmaster.govuk. 12 2 3 4 5",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.setup_many(root, {
                "gov.txt.gz": gov, "example.txt.gz": example, "govuk.txt.gz": govuk
            })
            manifest = (root / "zones" / "manifest.json").read_bytes()
            original_gov = (root / "zones" / "gov.txt.gz").read_bytes()
            extra = ("--exclude-zone", "gov")
            for invocation in (self.invoke, self.invoke_build):
                failed = invocation(root)
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("reason=record_fields_space_delimited", failed.stderr)
                self.assertNotIn("confidential.gov.", failed.stdout + failed.stderr)
            preflight = self.invoke(root, *extra)
            full = self.invoke_build(root, *extra)
            self.assertEqual(preflight.returncode, 0, preflight.stderr)
            self.assertEqual(full.returncode, 0, full.stderr)
            self.assertIn("Temporary CZDS exclusion: gov", preflight.stdout)
            coverage = (root / "coverage.txt").read_text(encoding="utf-8")
            counts = (root / "counts.txt").read_text(encoding="utf-8")
            self.assertIn("# coverage_complete=false", coverage)
            self.assertIn("# excluded_zones=gov", coverage)
            self.assertIn("coverage_complete=false", counts)
            self.assertIn("excluded_zones=gov", counts)
            self.assertIn("zones=2", counts)
            self.assertIn("example|", coverage)
            self.assertIn("govuk|", coverage)
            self.assertNotIn("\ngov|", coverage)
            self.assertEqual((root / "zones" / "manifest.json").read_bytes(), manifest)
            self.assertEqual((root / "zones" / "gov.txt.gz").read_bytes(), original_gov)
            private = (root / "private-counts.txt").read_text(encoding="utf-8")
            self.assertIn("ns1.example.net|1", private)
            self.assertIn("ns2.example.net|1", private)
            self.assertNotIn("ns.secret.example", private)

    def test_exclusion_fails_if_requested_zone_missing_or_is_only_zone(self):
        valid = [
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
            "a.example.\t3600\tIN\tNS\tns1.example.net.",
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
        ]
        for filenames in ({"example.txt.gz": valid}, {
            "gov.txt.gz": [
                "gov.\t3600\tIN\tNS\tns.gov.",
                "gov.\t3600\tIN\tSOA\tns.gov. hostmaster.gov. 1 2 3 4 5",
            ],
        }):
            with self.subTest(names=tuple(filenames)), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                self.setup_many(root, filenames)
                for invocation in (self.invoke, self.invoke_build):
                    failed = invocation(root, "--exclude-zone", "gov")
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertFalse((root / "counts.txt").exists())
                    self.assertNotIn("ns1.example.net", failed.stdout + failed.stderr)
                    unsupported = invocation(root, "--exclude-zone", "com")
                    self.assertNotEqual(unsupported.returncode, 0)

    def test_exclusion_never_hides_other_malformed_zones(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.setup_many(root, {
                "gov.txt.gz": [
                    "gov.\t3600\tIN\tNS\tns.gov.",
                    "gov.\t3600\tIN\tSOA\tns.gov. hostmaster.gov. 1 2 3 4 5",
                ],
                "example.txt.gz": [
                    "example.\t3600\tIN\tNS\tns.example.",
                    "private.example. 3600 IN NS ns.secret.example.",
                    "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
                ],
            })
            for invocation in (self.invoke, self.invoke_build):
                failed = invocation(root, "--exclude-zone", "gov")
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("reason=record_fields_space_delimited", failed.stderr)
                self.assertNotIn("private.example.", failed.stdout + failed.stderr)

    def test_nonleading_soa_is_validated_without_private_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.setup_fixture(
                root,
                "gov.txt.gz",
                [
                    "gov.\t3600\tIN\tNS\tns.gov.",
                    "private-name.gov.\t3600\tIN\tNS\tns.secret.example.",
                    "gov.\t3600\tIN\tSOA\tns.gov. hostmaster.gov. 123 2 3 4 5",
                ],
            )
            result = self.invoke(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Non-leading SOA preflight completed: 1 files", result.stdout)
            self.assertNotIn("private-name.gov", result.stdout + result.stderr)
            self.assertNotIn("ns.secret.example", result.stdout + result.stderr)

    def test_missing_soa_fails_without_leaking_owner(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.setup_fixture(
                root, "gov.txt.gz", ["private-name.gov.\t3600\tIN\tNS\tns.secret.example."]
            )
            result = self.invoke(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("failed non-leading SOA preflight for gov.txt.gz", result.stderr)
            self.assertNotIn("private-name.gov", result.stdout + result.stderr)
            self.assertNotIn("ns.secret.example", result.stdout + result.stderr)

    def test_standard_leading_soa_does_not_get_reparsed(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.setup_fixture(
                root,
                "gov.txt.gz",
                [
                    "gov.\t3600\tIN\tSOA\tns.gov. hostmaster.gov. 123 2 3 4 5",
                    "a.gov.\t3600\tIN\tNS\tns1.example.net.",
                    "gov.\t3600\tIN\tSOA\tns.gov. hostmaster.gov. 123 2 3 4 5",
                ],
            )
            result = self.invoke(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("preflight completed: 0 files", result.stdout)

    def test_failure_reasons_are_safe_and_match_full_aggregation(self):
        # Every specimen is synthetic. The real licensed .gov input is unavailable
        # to public CI, so the actual production failure reason is not asserted.
        initial = "gov.\t3600\tIN\tNS\tns.gov."
        soa = "gov.\t3600\tIN\tSOA\tns.gov. hostmaster.gov. 123 2 3 4 5"
        cases = {
            "record_blank": [initial, "", soa],
            "record_fields_comment": [initial, "  ; private-name.gov. hidden", soa],
            "record_fields_directive": [initial, "  $ORIGIN private-name.gov.", soa],
            "record_fields_space_delimited": [
                initial, "private-name.gov. 3600 IN NS ns.hidden.example.", soa
            ],
            "record_fields_missing_tabs": [initial, "private-name.gov.", soa],
            "record_fields_partial_tabs": [
                initial, "private-name.gov.\t3600\tIN\tNS", soa
            ],
            "record_fields_mixed_delimiters": [
                initial, "private-name.gov.\t3600 IN NS ns.hidden.example.", soa
            ],
            "soa_missing": [initial, "private-name.gov.\t3600\tIN\tNS\tns.hidden.example."],
            "soa_final_missing": [
                initial, soa, "private-name.gov.\t3600\tIN\tNS\tns.hidden.example."
            ],
            "soa_owner_class": [
                initial, "other.\t3600\tIN\tSOA\tns.other. hostmaster.other. 123 2 3 4 5"
            ],
            "soa_serial_invalid": [initial, "gov.\t3600\tIN\tSOA\tinvalid"],
            "soa_serial_mismatch": [
                initial, soa,
                "gov.\t3600\tIN\tSOA\tns.gov. hostmaster.gov. 124 2 3 4 5",
            ],
            "after_final_soa": [
                initial, soa, soa, "private-name.gov.\t3600\tIN\tA\t192.0.2.1"
            ],
            "ns_owner_outside_apex": [
                initial, "private-name.example.\t3600\tIN\tNS\tns.hidden.example.", soa
            ],
            "ns_owner_order": [
                initial, "z.gov.\t3600\tIN\tNS\tns.hidden.example.",
                "a.gov.\t3600\tIN\tNS\tns.hidden.example.", soa,
            ],
            "ns_rdata_extra": [
                initial, "private-name.gov.\t3600\tIN\tNS\tns.hidden.example. invalid", soa
            ],
            "ns_target_root": [
                initial, "private-name.gov.\t3600\tIN\tNS\t.", soa
            ],
            "dns_name_non_ascii": [
                initial, "privaté.gov.\t3600\tIN\tNS\tns.hidden.example.", soa
            ],
        }
        for reason, records in cases.items():
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d)
                self.setup_fixture(root, "gov.txt.gz", records)
                preflight = self.invoke(root)
                full = self.invoke_build(root)
                self.assertNotEqual(preflight.returncode, 0, preflight.stdout)
                self.assertNotEqual(full.returncode, 0, full.stdout)
                self.assertIn(f"reason={reason}", preflight.stderr)
                self.assertIn(f"reason={reason}", full.stderr)
                for result in (preflight, full):
                    output = result.stdout + result.stderr
                    self.assertNotIn("private-name", output)
                    self.assertNotIn("ns.hidden.example", output)
                    self.assertNotIn("hostmaster.gov", output)
                    self.assertNotIn("privaté.gov", output)

    def test_first_record_format_reason_matches_full_aggregation(self):
        # Both CLI entry points must use the same structural classifier,
        # including the preflight header check before process_input().
        cases = {
            "record_blank": "",
            "record_fields_comment": "; private-name.gov. confidential",
            "record_fields_directive": "$TTL 3600",
            "record_fields_space_delimited": "private-name.gov. 3600 IN NS ns.hidden.example.",
            "record_fields_missing_tabs": "private-name.gov.",
            "record_fields_partial_tabs": "private-name.gov.\t3600\tIN\tNS",
            "record_fields_mixed_delimiters": "private-name.gov.\t3600 IN NS ns.hidden.example.",
        }
        final = "gov.\t3600\tIN\tSOA\tns.gov. hostmaster.gov. 123 2 3 4 5"
        for reason, first in cases.items():
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d)
                self.setup_fixture(root, "gov.txt.gz", [first, final])
                preflight = self.invoke(root)
                build = self.invoke_build(root)
                self.assertNotEqual(preflight.returncode, 0)
                self.assertNotEqual(build.returncode, 0)
                for result in (preflight, build):
                    output = result.stdout + result.stderr
                    self.assertIn(f"reason={reason}", output)
                    self.assertNotIn("private-name.gov.", output)
                    self.assertNotIn("ns.hidden.example", output)
                    self.assertNotIn("hostmaster.gov", output)

    def test_nonleading_soa_and_glue_deduplicate_in_both_paths(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.setup_fixture(
                root, "gov.txt.gz",
                [
                    "gov.\t3600\tIN\tNS\tns.gov.",
                    "a.gov.\t3600\tIN\tNS\tNS.Hidden.Example.",
                    "host.a.gov.\t3600\tIN\tA\t192.0.2.3",
                    "a.gov.\t3600\tIN\tNS\tns.hidden.example.",
                    "gov.\t3600\tIN\tSOA\tns.gov. hostmaster.gov. 123 2 3 4 5",
                ]
            )
            preflight = self.invoke(root)
            full = self.invoke_build(root)
            self.assertEqual(preflight.returncode, 0, preflight.stderr)
            self.assertEqual(full.returncode, 0, full.stderr)
            self.assertEqual(
                (root / "private-counts.txt").read_text(encoding="utf-8").splitlines(),
                ["# format=nameserver|delegations", "ns.hidden.example|1"],
            )
            self.assertIn("delegation_edges=1", (root / "counts.txt").read_text(encoding="utf-8"))
            self.assertNotIn("ns.hidden.example", preflight.stdout + preflight.stderr)

    def test_plain_valueerror_cannot_inject_exception_text(self):
        # A third-party validation exception is deliberately not made public.
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.setup_fixture(
                root, "gov.txt.gz",
                ["gov.\t3600\tIN\tNS\tns.gov.", "gov.\t3600\tIN\tSOA\tns.gov. hostmaster.gov. 123 2 3 4 5"],
            )
            sys.path.insert(0, str(ROOT / "scripts"))
            try:
                from build_nsdb import public_validation_code
                self.assertEqual(
                    public_validation_code(ValueError("secret.internal.example.")),
                    "unclassified_error",
                )
            finally:
                sys.path.remove(str(ROOT / "scripts"))


if __name__ == "__main__":
    unittest.main()
