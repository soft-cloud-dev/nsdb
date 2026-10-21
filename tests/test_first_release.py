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
            counts.write_text("zones=1\ndelegation_edges=9\nnameservers_total=2\n")
            coverage = root / "coverage.txt"
            coverage.write_text("# format=zone|soa_serial|records|delegated_names|delegation_edges\nexample|1|10|6|9\n")
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

    def test_release_payload_checksum_and_attestation_input(self):
        with tempfile.TemporaryDirectory() as temp:
            out = pathlib.Path(temp)
            for name in ASSETS.ARTIFACTS:
                (out / name).write_bytes(b"public\n")
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
            (out / "nameservers.txt").write_text("public\n")
            (out / "private-counts.txt").write_text("secret\n")
            with self.assertRaisesRegex(ValueError, "allowlist"):
                ASSETS.verify(out)


if __name__ == "__main__":
    unittest.main()
