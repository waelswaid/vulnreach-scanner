"""Unit tests for pipeline.record: records, confidence, cross-check, overrides, index.

Run from the repository root:
    python -m unittest tests.test_record
"""

import json
import tempfile
import unittest
from pathlib import Path

from pipeline import record

SPEC_KEYS = {
    "id", "aliases", "package", "ecosystem", "repo", "status", "fix_commits",
    "rejected_commits", "vulnerable", "entry_points", "names_verified_for", "notes",
    "overrides_applied", "pipeline_version", "osv_modified", "generated_at",
}


def merged_advisory(**overrides):
    base = {
        "id": "GHSA-8q59-q68h-6hv4",
        "aliases": ["CVE-2020-14343", "PYSEC-2021-142"],
        "package": "pyyaml",
        "ecosystem": "PyPI",
        "modified": "2026-02-04T03:33:10Z",
        "summary_text": "Improper Input Validation in PyYAML",
        "links": [],
        "git_ranges": [],
        "affected_versions": ["5.3", "5.3.1"],
        "fixed_versions": ["5.4"],
        "raw": [],
    }
    base.update(overrides)
    return base


def analysis(**overrides):
    base = {
        "repo": "https://github.com/yaml/pyyaml",
        "status": "found",
        "fix_commits": [
            {"sha": "a001f2782501ad2d24986959f0239a354675f9dc", "source": "commit_link",
             "in_fixed_release": True, "bundle": False},
        ],
        "rejected_commits": [],
        "vulnerable": [
            {"name": "yaml.constructor", "kind": "module_level", "file": "lib3/yaml/constructor.py",
             "commit": "a001f2782501ad2d24986959f0239a354675f9dc",
             "evidence": ["module-level statement changed or removed: ..."]},
        ],
        "entry_points": [
            {"name": "yaml.full_load", "defined_as": "yaml.full_load", "confidence": "high",
             "path": ["yaml.full_load", "yaml.load", "yaml.constructor"]},
        ],
        "names_verified_for": [">=5.1, <5.4"],
        "notes": [],
    }
    base.update(overrides)
    return base


class ConfidenceTest(unittest.TestCase):
    def test_confidence_high_requires_release_check_and_no_bundle(self):
        self.assertEqual(record.commit_confidence({"in_fixed_release": True, "bundle": False}), "high")
        self.assertEqual(record.commit_confidence({"in_fixed_release": True, "bundle": True}), "medium")

    def test_confidence_medium_when_unchecked_or_bundle(self):
        self.assertEqual(record.commit_confidence({"in_fixed_release": None, "bundle": False}), "medium")
        self.assertEqual(record.commit_confidence({"in_fixed_release": None, "bundle": True}), "medium")


class CrossCheckTest(unittest.TestCase):
    def test_text_cross_check_matches_and_records_misses(self):
        text = ("Specially crafted inputs to idna.encode() can take long; "
                "extract_zipped_paths() is also mentioned, and nothing_here() matches no name.")
        names = ["idna.core.encode", "requests.utils.extract_zipped_paths", "idna.core.decode"]
        self.assertEqual(record.text_cross_check(text, names), {
            "matched": ["idna.core.encode", "requests.utils.extract_zipped_paths"],
            "unmatched_mentions": ["nothing_here"],
        })

    def test_cross_check_match_raises_function_confidence(self):
        merged = merged_advisory(summary_text="Calls to yaml.full_load() ... see construct_python_object_new()")
        vulnerable = [
            {"name": "yaml.constructor.FullConstructor.construct_python_object_new", "kind": "method",
             "confidence": "medium", "evidence": ["modified"]},
            {"name": "yaml.constructor.FullConstructor.set_python_instance_state", "kind": "method",
             "confidence": "medium", "evidence": ["modified"]},
        ]
        built = record.build_record(merged, analysis(vulnerable=vulnerable))
        by_name = {v["name"]: v for v in built["vulnerable"]}
        raised = by_name["yaml.constructor.FullConstructor.construct_python_object_new"]
        self.assertEqual(raised["confidence"], "high")
        self.assertTrue(any("advisory text" in e for e in raised["evidence"]))
        self.assertEqual(by_name["yaml.constructor.FullConstructor.set_python_instance_state"]["confidence"],
                         "medium")


class BuildRecordTest(unittest.TestCase):
    def test_build_record_matches_spec_shape(self):
        built = record.build_record(merged_advisory(), analysis())
        self.assertEqual(set(built), SPEC_KEYS)
        self.assertEqual(built["id"], "GHSA-8q59-q68h-6hv4")
        self.assertEqual(built["aliases"], ["CVE-2020-14343", "PYSEC-2021-142"])
        self.assertEqual(built["package"], "pyyaml")
        self.assertEqual(built["repo"], "https://github.com/yaml/pyyaml")
        self.assertEqual(built["status"], "found")
        self.assertEqual(built["pipeline_version"], record.PIPELINE_VERSION)
        self.assertEqual(built["osv_modified"], "2026-02-04T03:33:10Z")
        self.assertEqual(built["overrides_applied"], [])
        self.assertRegex(built["generated_at"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertEqual(built["fix_commits"], analysis()["fix_commits"])
        self.assertEqual(built["entry_points"], analysis()["entry_points"])
        self.assertEqual(built["names_verified_for"], [">=5.1, <5.4"])
        vuln = built["vulnerable"][0]
        self.assertEqual(set(vuln), {"name", "kind", "file", "confidence", "evidence"})
        # confidence comes from the commit the function was found in
        self.assertEqual(vuln["confidence"], "high")

    def test_vulnerable_confidence_follows_commit(self):
        bundled = analysis(fix_commits=[{"sha": "a001f2782501ad2d24986959f0239a354675f9dc",
                                         "source": "commit_link", "in_fixed_release": True, "bundle": True}])
        built = record.build_record(merged_advisory(), bundled)
        self.assertEqual(built["vulnerable"][0]["confidence"], "medium")


class OverridesTest(unittest.TestCase):
    OVERRIDES = {
        "GHSA-8q59-q68h-6hv4": {
            "add_vulnerable": [{"name": "yaml.constructor.FullConstructor.construct_python_object_new",
                                "kind": "method", "evidence": ["hand-checked: registration moved"]}],
            "remove_vulnerable": ["yaml.constructor"],
            "add_entry_points": [{"name": "yaml.CFullLoader", "defined_as": "yaml.cyaml.CFullLoader"}],
            "remove_entry_points": ["yaml.full_load"],
            "note": "checked by hand on 2026-11-03",
        },
        "GHSA-xxxx-certifi": {"status": "not_code", "fix_commits": ["bd8153872e9c6fc98f4023df9c2deaffea2fa463"]},
    }

    def test_overrides_add_remove_and_mark_not_code(self):
        built = record.build_record(merged_advisory(), analysis())
        changed = record.apply_overrides(built, self.OVERRIDES)
        self.assertEqual([v["name"] for v in changed["vulnerable"]],
                         ["yaml.constructor.FullConstructor.construct_python_object_new"])
        self.assertEqual(changed["vulnerable"][0]["confidence"], "high")
        self.assertEqual([e["name"] for e in changed["entry_points"]], ["yaml.CFullLoader"])
        self.assertIn("checked by hand on 2026-11-03", changed["notes"])
        self.assertEqual(len(changed["overrides_applied"]), 5)
        self.assertEqual(built["overrides_applied"], [])  # input not mutated

        certifi = record.build_record(
            merged_advisory(id="GHSA-xxxx-certifi", package="certifi"),
            analysis(status="found", vulnerable=[{"name": "certifi", "kind": "module_level", "evidence": []}]),
        )
        changed = record.apply_overrides(certifi, self.OVERRIDES)
        self.assertEqual(changed["status"], "not_code")
        self.assertEqual([c["sha"] for c in changed["fix_commits"]],
                         ["bd8153872e9c6fc98f4023df9c2deaffea2fa463"])
        self.assertEqual(changed["fix_commits"][0]["source"], "override")

        untouched = record.apply_overrides(record.build_record(merged_advisory(id="GHSA-none"), analysis()),
                                           self.OVERRIDES)
        self.assertEqual(untouched["overrides_applied"], [])

    def test_overrides_survive_rebuild(self):
        first = record.apply_overrides(record.build_record(merged_advisory(), analysis()), self.OVERRIDES)
        second = record.apply_overrides(record.build_record(merged_advisory(), analysis()), self.OVERRIDES)
        first.pop("generated_at")
        second.pop("generated_at")
        self.assertEqual(first, second)


class WriteTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_write_record_path_and_roundtrip(self):
        built = record.build_record(merged_advisory(), analysis())
        path = record.write_record(built, self.out)
        self.assertEqual(path, self.out / "GHSA-8q59-q68h-6hv4.json")
        text = path.read_text(encoding="utf-8")
        self.assertTrue(text.endswith("}\n"))
        self.assertEqual(json.loads(text), built)
        self.assertEqual(list(json.loads(text)), sorted(built))

    def test_write_index_maps_ids_and_aliases(self):
        record.write_record(record.build_record(merged_advisory(), analysis()), self.out)
        record.write_record(
            record.build_record(merged_advisory(id="GHSA-6757-jp84-gxfx", aliases=["CVE-2020-1747"]),
                                analysis()),
            self.out,
        )
        path = record.write_index(self.out)
        self.assertEqual(path, self.out / "index.json")
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {
            "GHSA-8q59-q68h-6hv4": "GHSA-8q59-q68h-6hv4",
            "CVE-2020-14343": "GHSA-8q59-q68h-6hv4",
            "PYSEC-2021-142": "GHSA-8q59-q68h-6hv4",
            "GHSA-6757-jp84-gxfx": "GHSA-6757-jp84-gxfx",
            "CVE-2020-1747": "GHSA-6757-jp84-gxfx",
        })
        # rebuilding overwrites and never indexes the index itself
        self.assertEqual(record.write_index(self.out), path)
        self.assertNotIn("index", json.loads(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
