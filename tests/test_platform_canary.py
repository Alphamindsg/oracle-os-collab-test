import copy
import json
import unittest
from pathlib import Path

from platform_canary import validate

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / "platform-canary.json").read_text(encoding="utf-8"))


class PlatformCanaryTests(unittest.TestCase):
    def test_reference_canary_passes(self):
        self.assertEqual(validate(CONTRACT, "a" * 40), [])

    def test_closed_blocker_requires_disposition(self):
        candidate = copy.deepcopy(CONTRACT)
        candidate["shared_blockers"][0]["dispositions"] = {}
        errors = validate(candidate, "b" * 40)
        self.assertTrue(any("lacks terminal disposition" in e for e in errors))

    def test_dependency_cycle_is_rejected(self):
        candidate = copy.deepcopy(CONTRACT)
        candidate["dependency_edges"].append(["source:pfo-pr34", "canary"])
        self.assertIn("dependency graph contains a cycle", validate(candidate, "c" * 40))

    def test_material_defect_requires_regression_guard_and_applicability(self):
        candidate = copy.deepcopy(CONTRACT)
        candidate["defects"][0]["regression_guard"] = ""
        candidate["defects"][0]["applicability"] = {}
        errors = validate(candidate, "d" * 40)
        self.assertTrue(any("lacks regression_guard" in e for e in errors))
        self.assertTrue(any("lacks applicability decision" in e for e in errors))

    def test_weak_source_sha_is_rejected(self):
        candidate = copy.deepcopy(CONTRACT)
        candidate["source"]["head_sha"] = "latest"
        self.assertTrue(any("source evidence requires" in e for e in validate(candidate, "e" * 40)))

    def test_secret_or_authority_field_is_rejected(self):
        candidate = copy.deepcopy(CONTRACT)
        candidate["consumer"]["api_token"] = "redacted"
        self.assertTrue(any("forbidden shared authority/secret field" in e for e in validate(candidate, "f" * 40)))

    def test_runtime_head_must_be_exact_sha(self):
        self.assertIn("runtime exact head must be a 40-hex SHA", validate(CONTRACT, "HEAD"))


if __name__ == "__main__":
    unittest.main()
