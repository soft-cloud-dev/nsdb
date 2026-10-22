import importlib.util
import gzip
import hashlib
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_release_assets", ROOT / "scripts" / "verify_release_assets.py")
ASSETS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSETS)


class InitialReleaseTests(unittest.TestCase):
    def test_first_release_is_verified_and_contains_no_private_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            private = root / "private.txt"
            private.write_text("# format=nameserver|delegations\nns.hidden.example|4\nns.visible.example|5\n")
            counts = root / "counts.txt"
            counts.write_text("zones=1\ncoverage_complete=true\nexcluded_zones=none\ndelegation_edges=9\nnameservers_total=2\n")
            coverage = root / "coverage.txt"
            coverage.write_text("# format=zone|soa_serial|records|delegated_names|delegation_edges\n# coverage_complete=true\n# excluded_zones=none\nexample|1|10|6|9\n")
            out = root / "dist"
            subprocess.run([
                sys.executable, str(ROOT / "scripts" / "publish_nsdb.py"),
                "--current-private", str(private),
                "--current-full-counts", str(counts),
                "--current-coverage", str(coverage),
                "--k", "5", "--current-tag", "nsdb-2026-10-21",
                "--previous-tag", "none", "--out", str(out),
            ], check=True)
            verify = [
                sys.executable, str(ROOT / "scripts" / "verify_public.py"),
                "--current", str(out / "nameservers.txt"),
                "--delegation-changes", str(out / "delegation-changes.txt"),
                "--nameserver-changes", str(out / "nameserver-changes.txt"),
            ]
            subprocess.run(verify, check=True)
            self.assertNotIn("ns.hidden.example", (out / "nameservers.txt").read_text())
            self.assertNotIn("ns.visible.example", (out / "delegation-changes.txt").read_text())
            self.assertIn("# previous=none", (out / "delegation-changes.txt").read_text())
            with (out / "delegation-changes.txt").open("a") as fh:
                fh.write("ns.hidden.example|<5|5|NA\n")
            self.assertNotEqual(subprocess.run(verify, capture_output=True).returncode, 0)

    def test_partial_snapshot_is_labeled_and_restoration_breaks_comparison(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            private = root / "private.txt"
            private.write_text("# format=nameserver|delegations\nns.visible.example|5\n")
            counts = root / "counts.txt"
            coverage = root / "coverage.txt"

            def source(complete, excluded, rows, edges, zones):
                counts.write_text(
                    f"zones={zones}\ncoverage_complete={complete}\n"
                    f"excluded_zones={excluded}\ndelegation_edges={edges}\n"
                    "nameservers_total=1\n", encoding="utf-8"
                )
                coverage.write_text(
                    "# format=zone|soa_serial|records|delegated_names|delegation_edges\n"
                    f"# coverage_complete={complete}\n# excluded_zones={excluded}\n"
                    + rows,
                    encoding="utf-8",
                )

            def publish(directory, previous=None):
                command = [
                    sys.executable, str(ROOT / "scripts" / "publish_nsdb.py"),
                    "--current-private", str(private),
                    "--current-full-counts", str(counts),
                    "--current-coverage", str(coverage),
                    "--k", "5", "--current-tag", "nsdb-2026-10-22",
                    "--previous-tag", "none" if previous is None else "nsdb-2026-10-21",
                    "--out", str(directory),
                ]
                if previous is not None:
                    command += [
                        "--previous-public", str(previous / "nameservers.txt"),
                        "--previous-full-counts", str(previous / "counts.txt"),
                        "--previous-coverage", str(previous / "coverage.txt"),
                    ]
                return subprocess.run(command, capture_output=True, text=True)

            source("false", "gov", "example|1|10|6|5\n", 5, 1)
            previous = root / "partial"
            self.assertEqual(publish(previous).returncode, 0)
            for file, prefix in (
                ("coverage.txt", "# "), ("nameservers.txt", "# "),
                ("delegation-changes.txt", "# "),
                ("nameserver-changes.txt", "# "),
                ("counts.txt", ""), ("changes-counts.txt", ""),
            ):
                contents = (previous / file).read_text(encoding="utf-8")
                self.assertIn(prefix + "coverage_complete=false", contents)
                self.assertIn(prefix + "excluded_zones=gov", contents)
            self.assertIn("comparison_break=true", (previous / "changes-counts.txt").read_text())

            valid = root / "complete"
            source("true", "none", "example|1|10|6|5\ngov|1|10|0|0\n", 5, 2)
            outcome = publish(valid, previous)
            self.assertEqual(outcome.returncode, 0, outcome.stderr)
            changes = (valid / "changes-counts.txt").read_text()
            self.assertIn("coverage_complete=true", changes)
            self.assertIn("excluded_zones=none", changes)
            self.assertIn("coverage_changed=true", changes)
            self.assertIn("comparison_break=true", changes)
            check = subprocess.run([
                sys.executable, str(ROOT / "scripts" / "verify_public.py"),
                "--previous", str(previous / "nameservers.txt"),
                "--current", str(valid / "nameservers.txt"),
                "--delegation-changes", str(valid / "delegation-changes.txt"),
                "--nameserver-changes", str(valid / "nameserver-changes.txt"),
            ], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stderr)

    def test_inconsistent_partial_coverage_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            private = root / "private.txt"
            private.write_text("# format=nameserver|delegations\nns.secret.example|7\n")
            counts = root / "counts.txt"
            counts.write_text("zones=1\ncoverage_complete=true\nexcluded_zones=none\n")
            coverage = root / "coverage.txt"
            coverage.write_text(
                "# format=zone|soa_serial|records|delegated_names|delegation_edges\n"
                "# coverage_complete=false\n# excluded_zones=gov\nexample|1|10|6|7\n"
            )
            result = subprocess.run([
                sys.executable, str(ROOT / "scripts" / "publish_nsdb.py"),
                "--current-private", str(private),
                "--current-full-counts", str(counts),
                "--current-coverage", str(coverage),
                "--k", "5", "--current-tag", "nsdb-2026-10-22",
                "--out", str(root / "dist"),
            ], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("ns.secret.example", result.stdout + result.stderr)

    def test_release_payload_checksum_and_attestation_input(self):
        with tempfile.TemporaryDirectory() as temp:
            out = pathlib.Path(temp)
            metadata = {
                "nameservers.txt": "# k=5\n# coverage_complete=true\n# excluded_zones=none\n",
                "coverage.txt": "# coverage_complete=true\n# excluded_zones=none\n",
                "delegation-changes.txt": "# coverage_complete=true\n# excluded_zones=none\n",
                "nameserver-changes.txt": "# coverage_complete=true\n# excluded_zones=none\n",
                "counts.txt": "coverage_complete=true\nexcluded_zones=none\n",
                "changes-counts.txt": "coverage_complete=true\nexcluded_zones=none\n",
            }
            for name in ASSETS.ARTIFACTS:
                (out / name).write_text(metadata.get(name, "public\n"), encoding="utf-8")
            original_snapshot = (out / "nameservers.txt").read_bytes()
            for name, compressed in ASSETS.GZIP_PAIRS:
                with (out / compressed).open("wb") as raw:
                    with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as stream:
                        stream.write((out / name).read_bytes())
            sums = "".join(
                f"{hashlib.sha256((out / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ASSETS.ARTIFACTS
            )
            (out / "SHA256SUMS").write_text(sums)
            ASSETS.verify(out)
            (out / "nameservers.txt").write_text("tampered\n")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                ASSETS.verify(out)
            (out / "nameservers.txt").write_bytes(original_snapshot)
            (out / "private-counts.txt").write_text("secret\n")
            with self.assertRaisesRegex(ValueError, "allowlist"):
                ASSETS.verify(out)


if __name__ == "__main__":
    unittest.main()
