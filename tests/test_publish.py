import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publish_nsdb", ROOT / "scripts" / "publish_nsdb.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class DiffTests(unittest.TestCase):
    def test_exact_change(self):
        changes, crossings = MOD.build_diff({"ns.example": 8}, {"ns.example": 11}, 5)
        self.assertEqual(changes, [("ns.example", "8", "11", "+3")])
        self.assertEqual(crossings, [])

    def test_threshold_entry_redacts_previous(self):
        changes, crossings = MOD.build_diff({}, {"ns.example": 5}, 5)
        self.assertEqual(changes, [("ns.example", "<5", "5", "NA")])
        self.assertEqual(crossings, [("+", "ns.example")])

    def test_threshold_exit_redacts_current(self):
        changes, crossings = MOD.build_diff({"ns.example": 7}, {}, 5)
        self.assertEqual(changes, [("ns.example", "7", "<5", "NA")])
        self.assertEqual(crossings, [("-", "ns.example")])

    def test_hidden_to_hidden_is_not_observable(self):
        changes, crossings = MOD.build_diff({}, {}, 5)
        self.assertEqual(changes, [])
        self.assertEqual(crossings, [])

    def test_lowered_k_uses_previous_visibility_threshold_in_redaction(self):
        changes, crossings = MOD.build_diff(
            {},
            {"ns.example": 8},
            current_k=5,
            previous_k=10,
        )
        self.assertEqual(changes, [("ns.example", "<10", "8", "NA")])
        self.assertEqual(crossings, [("+", "ns.example")])

    def test_transition_truth_table_small_domain(self):
        for k in range(2, 8):
            for previous in range(0, 12):
                for current in range(0, 12):
                    prev_visible = {"ns.example": previous} if previous >= k else {}
                    cur_visible = {"ns.example": current} if current >= k else {}
                    changes, crossings = MOD.build_diff(prev_visible, cur_visible, k)

                    if previous < k and current < k:
                        self.assertEqual(changes, [])
                        self.assertEqual(crossings, [])
                    elif previous == current:
                        self.assertEqual(changes, [])
                        self.assertEqual(crossings, [])
                    elif previous >= k and current >= k:
                        self.assertEqual(
                            changes,
                            [("ns.example", str(previous), str(current), f"{current - previous:+d}")],
                        )
                        self.assertEqual(crossings, [])
                    elif previous < k <= current:
                        self.assertEqual(
                            changes,
                            [("ns.example", f"<{k}", str(current), "NA")],
                        )
                        self.assertEqual(crossings, [("+", "ns.example")])
                    else:
                        self.assertEqual(
                            changes,
                            [("ns.example", str(previous), f"<{k}", "NA")],
                        )
                        self.assertEqual(crossings, [("-", "ns.example")])

    def test_crossings_are_projection_of_redacted_rows(self):
        prev = {"a": 5, "b": 9, "c": 12}
        cur = {"b": 10, "c": 12, "d": 7}
        changes, crossings = MOD.build_diff(prev, cur, 5)
        projected = []
        for name, previous, current, delta in changes:
            if previous == "<5":
                projected.append(("+", name))
            elif current == "<5":
                projected.append(("-", name))
        self.assertEqual(crossings, projected)


if __name__ == "__main__":
    unittest.main()
