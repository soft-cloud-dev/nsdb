import importlib.util
import io
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_nsdb", ROOT / "scripts" / "build_nsdb.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class DummyAggregate:
    def __init__(self):
        self.values = []

    def add(self, nameserver):
        self.values.append(nameserver)


def zone(*records):
    return io.StringIO("\n".join(records) + "\n")


class BuildTests(unittest.TestCase):
    def test_dns_names_are_ascii_lowercased_and_trailing_dot_removed(self):
        self.assertEqual(MOD.normalize_name("NS1.Cloudflare.Com."), "ns1.cloudflare.com")

    def test_unicode_name_is_rejected_instead_of_silently_normalized(self):
        with self.assertRaises(ValueError):
            MOD.normalize_name("ns1.exämple.")

    def test_ns_rrset_is_deduplicated_after_case_folding(self):
        aggregate = DummyAggregate()
        stream = zone(
            "EXAMPLE.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
            "EXAMPLE.\t3600\tIN\tNS\tns.example.",
            "foo.EXAMPLE.\t3600\tIN\tNS\tNS1.Cloudflare.Com.",
            "foo.example.\t3600\tIN\tNS\tns1.cloudflare.com.",
            "EXAMPLE.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
        )
        result = MOD.process_zone_stream(stream, "fixture", (), aggregate)
        self.assertEqual(aggregate.values, ["ns1.cloudflare.com"])
        self.assertEqual(result["delegated_names"], 1)
        self.assertEqual(result["delegation_edges"], 1)

    def test_root_ns_target_is_rejected(self):
        aggregate = DummyAggregate()
        stream = zone(
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
            "foo.example.\t3600\tIN\tNS\t.",
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
        )
        with self.assertRaisesRegex(ValueError, "root/empty NS target"):
            MOD.process_zone_stream(stream, "fixture", (), aggregate)

    def test_special_zone_match_is_hierarchical(self):
        special = ("home.arpa", "10.in-addr.arpa")
        self.assertTrue(MOD.in_special_zone("home.arpa", special))
        self.assertTrue(MOD.in_special_zone("host.home.arpa", special))
        self.assertTrue(MOD.in_special_zone("1.10.in-addr.arpa", special))
        self.assertFalse(MOD.in_special_zone("examplehome.arpa", special))
        self.assertFalse(MOD.in_special_zone("example.com", special))


if __name__ == "__main__":
    unittest.main()
