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

    def test_decimal_master_escape_is_canonicalized_without_creating_a_label_boundary(self):
        self.assertEqual(
            MOD.normalize_name(r"foo\046bar.Example."),
            r"foo\046bar.example",
        )

    def test_escaped_backslash_is_canonicalized(self):
        self.assertEqual(
            MOD.normalize_name(r"foo\\bar.example."),
            r"foo\092bar.example",
        )

    def test_invalid_punycode_alabel_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid IDN A-label"):
            MOD.normalize_name("xn--.example.")

    def test_overlong_label_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exceeds 63 octets"):
            MOD.normalize_name(("a" * 64) + ".example.")

    def test_overlong_fqdn_is_rejected(self):
        name = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 62]) + "."
        with self.assertRaisesRegex(ValueError, "exceeds 255 wire octets"):
            MOD.normalize_name(name)

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

    def test_apex_ns_is_ignored_and_glue_is_not_counted(self):
        aggregate = DummyAggregate()
        stream = zone(
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
            "example.\t3600\tIN\tNS\tns.example.",
            "foo.example.\t3600\tIN\tA\t192.0.2.1",
            "foo.example.\t3600\tIN\tNS\tns1.example.net.",
            "ns1.example.net.\t3600\tIN\tA\t192.0.2.53",
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
        )
        result = MOD.process_zone_stream(stream, "fixture", (), aggregate)
        self.assertEqual(aggregate.values, ["ns1.example.net"])
        self.assertEqual(result["delegated_names"], 1)
        self.assertEqual(result["delegation_edges"], 1)

    def test_out_of_order_owner_is_rejected(self):
        aggregate = DummyAggregate()
        stream = zone(
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
            "z.example.\t3600\tIN\tNS\tns1.example.net.",
            "a.example.\t3600\tIN\tNS\tns2.example.net.",
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
        )
        with self.assertRaisesRegex(ValueError, "records are not ordered by owner"):
            MOD.process_zone_stream(stream, "fixture", (), aggregate)

    def test_locally_served_owner_and_target_are_excluded(self):
        aggregate = DummyAggregate()
        stream = zone(
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
            "a.example.\t3600\tIN\tNS\tns.home.arpa.",
            "b.example.\t3600\tIN\tNS\tns1.example.net.",
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
        )
        result = MOD.process_zone_stream(stream, "fixture", ("home.arpa",), aggregate)
        self.assertEqual(aggregate.values, ["ns1.example.net"])
        self.assertEqual(result["locally_served_ns_targets_excluded"], 1)

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
