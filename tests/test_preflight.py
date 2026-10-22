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
    def invoke(directory: pathlib.Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--zones-dir",
                str(directory / "zones"),
                "--special-zones",
                str(directory / "special-zones.txt"),
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


if __name__ == "__main__":
    unittest.main()
