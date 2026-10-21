import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fetch_special_zones", ROOT / "scripts" / "fetch_special_zones.py"
)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class SpecialZoneTests(unittest.TestCase):
    def test_registry_normalization_is_deterministic(self):
        text = """
Locally-Served DNS Zones

Last Updated
2025-06-16

Zone Description Reference
10.IN-ADDR.ARPA RFC1918 Zone [RFC6303]
HOME.ARPA Homenet Special-Use Domain [RFC8375]
default.service.arpa. Default domain for SRP updates [RFC9665]
"""
        original_minimum = MOD.parse_registry.__globals__.get("MINIMUM_ZONES")
        # parse_registry deliberately enforces the size of the real registry,
        # so exercise the normalization primitives through a realistic padded
        # fixture instead of weakening production validation.
        rows = [
            f"{i}.100.IN-ADDR.ARPA RFC6598 Zone [RFC7793]"
            for i in range(64, 128)
        ]
        rows.extend(
            [
                "10.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "16.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "17.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "18.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "19.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "20.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "21.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "22.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "23.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "24.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "25.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "26.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "27.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "28.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "29.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "30.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "31.172.IN-ADDR.ARPA RFC1918 Zone [RFC6303]",
                "HOME.ARPA Homenet Special-Use Domain [RFC8375]",
                "RESOLVER.ARPA Resolver Special-Use Domain [RFC9462]",
                "SERVICE.ARPA Service Registration Domain [RFC9665]",
                "default.service.arpa. Default domain for SRP updates [RFC9665]",
            ]
        )
        # Pad above the production sanity threshold with distinct valid ARPA
        # labels so the fixture exercises ordering and trailing-dot handling.
        rows.extend(
            f"x{i}.example.arpa Synthetic fixture [RFC0000]" for i in range(30)
        )
        fixture = "Last Updated\n2025-06-16\n" + "\n".join(rows)

        updated, zones = MOD.parse_registry(fixture)
        self.assertEqual(updated, "2025-06-16")
        self.assertEqual(zones, sorted(set(zones)))
        self.assertIn("home.arpa", zones)
        self.assertIn("default.service.arpa", zones)
        self.assertNotIn("HOME.ARPA", zones)

    def test_too_small_registry_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unexpectedly small"):
            MOD.parse_registry("Last Updated\n2025-06-16\n10.IN-ADDR.ARPA test\n")


if __name__ == "__main__":
    unittest.main()
