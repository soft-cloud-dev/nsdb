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

    def test_dns_label_with_xn_prefix_is_preserved_without_idna_decoding(self):
        # Reproduces the real CZDS nameserver rejected by run 39677851872.
        self.assertEqual(
            MOD.normalize_name("xn--ns-nt3n.rackspace.com."),
            "xn--ns-nt3n.rackspace.com",
        )
        # xn-- has meaning to IDNA consumers, but DNS matching requires
        # only valid label bytes and ASCII case folding.
        self.assertEqual(MOD.normalize_name("XN--.EXAMPLE."), "xn--.example")

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

    def test_apex_metadata_after_delegations_does_not_create_false_edges(self):
        # Some CZDS zones, including .biz, place apex records between
        # the sorted child records and the final duplicated SOA.
        aggregate = DummyAggregate()
        stream = zone(
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 2026102101 2 3 4 5",
            "0--0.biz.\t3600\tIN\tNS\tNS1.EXAMPLE.NET.",
            "zzz.biz.\t3600\tIN\tNS\txn--ns-nt3n.rackspace.com.",
            "biz.\t3600\tIN\tNSEC3PARAM\t1 0 0 -",
            "biz.\t3600\tIN\tDNSKEY\t257 3 8 AQAB",
            "biz.\t3600\tIN\tNS\tns.biz.",
            "biz.\t3600\tIN\tRRSIG\tNS 8 1 3600 20261025000000 20261021000000 1 biz. AA==",
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 2026102101 2 3 4 5",
        )
        result = MOD.process_zone_stream(stream, "biz-fixture", (), aggregate)
        self.assertEqual(
            sorted(aggregate.values),
            ["ns1.example.net", "xn--ns-nt3n.rackspace.com"],
        )
        self.assertEqual(result["delegated_names"], 2)
        self.assertEqual(result["delegation_edges"], 2)
        self.assertEqual(result["zone"], "biz")
        self.assertEqual(result["soa_serial"], "2026102101")

    def test_interleaved_apex_records_do_not_disable_child_owner_ordering(self):
        aggregate = DummyAggregate()
        stream = zone(
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
            "z.biz.\t3600\tIN\tNS\tns1.example.net.",
            "biz.\t3600\tIN\tDNSKEY\t257 3 8 AQAB",
            "a.biz.\t3600\tIN\tNS\tns2.example.net.",
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
        )
        with self.assertRaisesRegex(ValueError, "records are not ordered by owner"):
            MOD.process_zone_stream(stream, "biz-fixture", (), aggregate)

    def test_no_records_allowed_after_closing_soa_even_if_apex(self):
        aggregate = DummyAggregate()
        stream = zone(
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
            "a.biz.\t3600\tIN\tNS\tns1.example.net.",
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
            "biz.\t3600\tIN\tDNSKEY\t257 3 8 AQAB",
        )
        with self.assertRaisesRegex(ValueError, "records appear after final SOA"):
            MOD.process_zone_stream(stream, "biz-fixture", (), aggregate)

    def test_out_of_order_owner_is_rejected(self):
        aggregate = DummyAggregate()
        stream = zone(
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
            "z.example.\t3600\tIN\tNS\tns1.example.net.",
            "a.example.\t3600\tIN\tNS\tns2.example.net.",
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
        )
        with self.assertRaisesRegex(ValueError, "NS delegation owners violate both"):
            MOD.process_zone_stream(stream, "fixture", (), aggregate)

    def test_dnssec_canonical_order_accepts_ns1_biz_after_ns1_biz_news(self):
        # Reproduces the .biz transition from run 39678700349.
        # Dotted-string ordering rejects this, but right-to-left DNS label
        # ordering accepts it: biz-news < ns1 in the second-to-last label.
        aggregate = DummyAggregate()
        stream = zone(
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
            "ns1.biz-news.biz.\t3600\tIN\tNS\tns1.example.net.",
            "ns1.biz.\t3600\tIN\tNS\tns2.example.net.",
            "biz.\t3600\tIN\tDNSKEY\t257 3 8 AQAB",
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
        )
        result = MOD.process_zone_stream(stream, "biz-fixture", (), aggregate)
        self.assertEqual(result["delegated_names"], 2)
        self.assertEqual(result["delegation_edges"], 2)
        self.assertEqual(
            aggregate.values, ["ns1.example.net", "ns2.example.net"]
        )

    def test_glue_between_same_owner_ns_records_preserves_rrset(self):
        aggregate = DummyAggregate()
        stream = zone(
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
            "ns1.biz-news.biz.\t3600\tIN\tNS\tns1.example.net.",
            "a.ns1.biz-news.biz.\t3600\tIN\tA\t192.0.2.9",
            "ns1.biz-news.biz.\t3600\tIN\tNS\tns1.example.net.",
            "ns1.biz-news.biz.\t3600\tIN\tNS\tns2.example.net.",
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
        )
        result = MOD.process_zone_stream(stream, "biz-fixture", (), aggregate)
        self.assertEqual(result["delegated_names"], 1)
        self.assertEqual(result["delegation_edges"], 2)
        self.assertEqual(
            sorted(aggregate.values), ["ns1.example.net", "ns2.example.net"]
        )

    def test_plain_lexical_order_is_still_supported(self):
        # Two names can be plain-sorted but reverse-sorted canonically;
        # the input convention must be consistent across a whole zone.
        aggregate = DummyAggregate()
        stream = zone(
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
            "a.ns1.biz.\t3600\tIN\tNS\tns1.example.net.",
            "b.biz.\t3600\tIN\tNS\tns2.example.net.",
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
        )
        result = MOD.process_zone_stream(stream, "fixture", (), aggregate)
        self.assertEqual(result["delegated_names"], 2)
        self.assertEqual(result["delegation_edges"], 2)

    def test_inconsistent_ordering_modes_are_rejected(self):
        aggregate = DummyAggregate()
        stream = zone(
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
            # First pair is plain-increasing, canonical-decreasing.
            "a.ns1.biz.\t3600\tIN\tNS\tns1.example.net.",
            "b.biz.\t3600\tIN\tNS\tns2.example.net.",
            # Second pair is plain-decreasing, canonical-increasing.
            "a.biz.\t3600\tIN\tNS\tns3.example.net.",
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
        )
        with self.assertRaisesRegex(ValueError, "NS delegation owners violate both"):
            MOD.process_zone_stream(stream, "fixture", (), aggregate)

    def test_non_ns_records_do_not_affect_ordering(self):
        aggregate = DummyAggregate()
        stream = zone(
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
            "a.biz.\t3600\tIN\tNS\tns1.example.net.",
            "z.biz.\t3600\tIN\tA\t192.0.2.1",
            "b.biz.\t3600\tIN\tNS\tns2.example.net.",
            "biz.\t3600\tIN\tSOA\tns.biz. hostmaster.biz. 1 2 3 4 5",
        )
        result = MOD.process_zone_stream(stream, "fixture", (), aggregate)
        self.assertEqual(result["delegated_names"], 2)
        self.assertEqual(result["delegation_edges"], 2)

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

    def test_ns_rdata_with_extra_fields_is_rejected(self):
        aggregate = DummyAggregate()
        stream = zone(
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
            "foo.example.\t3600\tIN\tNS\tns1.example.net. unexpected",
            "example.\t3600\tIN\tSOA\tns.example. hostmaster.example. 1 2 3 4 5",
        )
        with self.assertRaisesRegex(ValueError, "extra RDATA fields"):
            MOD.process_zone_stream(stream, "fixture", (), aggregate)

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
