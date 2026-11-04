"""Unit tests for pipeline.record: records, confidence, cross-check, overrides, index.

Run from the repository root:
    python -m unittest tests.test_record
"""

import json
import tempfile
import unittest
from pathlib import Path

from pipeline import record
from pipeline.repos import PipelineError

SPEC_KEYS = {
    "id", "aliases", "package", "ecosystem", "repo", "status", "fix_commits",
    "rejected_commits", "vulnerable", "entry_points", "names_verified_for", "notes",
    "overrides_applied", "pipeline_version", "osv_modified", "generated_at",
    "review", "overrides_fingerprint",
}

REASON = {"item": "pkg.mod.f", "kind": "referenced_not_called", "file": "pkg/mod.py",
          "references": [{"file": "pkg/mod.py", "line": 9, "context": "value in dict literal TABLE"}],
          "dead_ends": []}
REASON_B = dict(REASON, item="pkg.mod.g")


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


class ReviewTest(unittest.TestCase):
    def open_record(self, reasons=None):
        reasons = [REASON] if reasons is None else reasons
        return record.build_record(merged_advisory(), analysis(review={"tree": "abc123", "reasons": reasons}))

    def test_review_open_when_reasons_and_found(self):
        built = record.build_record(merged_advisory(), analysis(review={"tree": "abc123", "reasons": [REASON]}))
        self.assertEqual(built["review"]["status"], "open")
        self.assertEqual(built["review"]["tree"], "abc123")
        self.assertEqual(built["review"]["reasons"], [REASON])
        self.assertEqual(built["review"]["resolve"], record.REVIEW_RESOLVE)
        self.assertEqual(record.REVIEW_RESOLVE, "Do not edit: resolve in data/overrides.json and rerun")
        self.assertIsNone(built["overrides_fingerprint"])
        self.assertEqual(record.PIPELINE_VERSION, "2")

    def test_review_none_when_no_reasons_or_not_found(self):
        built = record.build_record(merged_advisory(), analysis())
        self.assertEqual(built["review"], {"status": "none", "tree": None, "reasons": [],
                                           "resolve": record.REVIEW_RESOLVE})
        unknown = record.build_record(merged_advisory(), analysis(
            status="unknown", review={"tree": "abc123", "reasons": [REASON]}))
        self.assertEqual(unknown["review"]["status"], "none")
        self.assertEqual(unknown["review"]["reasons"], [])

    def test_build_record_copies_overrides_applied(self):
        built = record.build_record(merged_advisory(), analysis(overrides_applied=["status set to found"]))
        self.assertEqual(built["overrides_applied"], ["status set to found"])

    def test_override_commits_replaces_and_sets_status(self):
        base = analysis()
        out = record.override_commits(base, {"status": "not_code", "fix_commits": ["bd8153872e9c6fc9"]})
        self.assertEqual(out["status"], "not_code")
        self.assertEqual(out["fix_commits"], [{"sha": "bd8153872e9c6fc9", "source": "override",
                                               "in_fixed_release": None, "bundle": False}])
        self.assertEqual(len(out["overrides_applied"]), 2)
        self.assertEqual(base["status"], "found")
        self.assertNotIn("overrides_applied", base)
        self.assertEqual(record.override_commits(base, None)["status"], "found")

    def test_override_vulnerable_drops_reasons_of_removed_items(self):
        base = analysis(review={"tree": "t", "reasons": [REASON, REASON_B]},
                        vulnerable=[{"name": "pkg.mod.f", "evidence": []}, {"name": "pkg.mod.g", "evidence": []}])
        out = record.override_vulnerable(base, {"remove_vulnerable": ["pkg.mod.f"]})
        self.assertEqual([v["name"] for v in out["vulnerable"]], ["pkg.mod.g"])
        self.assertEqual([r["item"] for r in out["review"]["reasons"]], ["pkg.mod.g"])
        self.assertEqual(len(base["review"]["reasons"]), 2)

    def test_reviewed_without_note_raises(self):
        with self.assertRaises(PipelineError) as ctx:
            record.override_entry_points(self.open_record(), {"reviewed": ["pkg.mod.f"], "signed_off": True})
        self.assertIn("GHSA-8q59-q68h-6hv4", str(ctx.exception))

    def test_unsigned_reviewed_leaves_record_open(self):
        out = record.override_entry_points(self.open_record(), {"reviewed": ["pkg.mod.f"], "note": "n"})
        self.assertEqual(out["review"]["status"], "open")
        self.assertIn("reviewed: not applied, unsigned", out["overrides_applied"])
        out = record.override_entry_points(
            self.open_record(), {"reviewed": True, "note": "n", "signed_off": False})
        self.assertEqual(out["review"]["status"], "open")

    def test_signed_reviewed_resolves_when_all_items_covered(self):
        both = self.open_record([REASON, REASON_B])
        spec = {"reviewed": ["pkg.mod.f"], "note": "n", "signed_off": True}
        partial = record.override_entry_points(both, spec)
        self.assertEqual(partial["review"]["status"], "open")
        self.assertIn("reviewed pkg.mod.f", partial["overrides_applied"])
        spec["reviewed"] = ["pkg.mod.f", "pkg.mod.g"]
        done = record.override_entry_points(both, spec)
        self.assertEqual(done["review"]["status"], "resolved")
        everything = record.override_entry_points(both, {"reviewed": True, "note": "n", "signed_off": True})
        self.assertEqual(everything["review"]["status"], "resolved")

    def test_reviewed_name_without_open_reason_is_recorded(self):
        out = record.override_entry_points(
            record.build_record(merged_advisory(), analysis()),
            {"reviewed": ["x"], "note": "n", "signed_off": True})
        self.assertIn("reviewed x: no open reason", out["overrides_applied"])
        self.assertEqual(out["review"]["status"], "none")

    def test_not_code_override_clears_open_reasons(self):
        out = record.apply_overrides(self.open_record(), {"GHSA-8q59-q68h-6hv4": {"status": "not_code"}})
        self.assertEqual(out["review"]["status"], "none")
        self.assertEqual(out["review"]["reasons"], [])

    def test_apply_overrides_sets_fingerprint(self):
        spec = {"note": "n"}
        out = record.apply_overrides(self.open_record(), {"GHSA-8q59-q68h-6hv4": spec})
        self.assertEqual(out["overrides_fingerprint"], record.overrides_fingerprint(spec))

    def test_validate_overrides_rejects_bad_specs(self):
        record.validate_overrides({"A": {"reviewed": ["x"], "note": "n", "signed_off": True}})
        record.validate_overrides({"A": {"reviewed": True, "note": "n"}})
        for spec in ({"reviewed": ["x"]}, {"reviewed": "x", "note": "n"}, {"reviewed": [1], "note": "n"},
                     {"reviewed": False, "note": "n"}, {"signed_off": "yes"}):
            with self.assertRaises(PipelineError) as ctx:
                record.validate_overrides({"GHSA-bad": spec})
            self.assertIn("GHSA-bad", str(ctx.exception))

    def test_fingerprint_is_stable_and_none_when_absent(self):
        a = record.overrides_fingerprint({"note": "n", "status": "found"})
        b = record.overrides_fingerprint({"status": "found", "note": "n"})
        self.assertEqual(a, b)
        self.assertRegex(a, r"^[0-9a-f]{64}$")
        self.assertNotEqual(a, record.overrides_fingerprint({"note": "m"}))
        self.assertIsNone(record.overrides_fingerprint(None))
        self.assertIsNone(record.overrides_fingerprint({}))


class PlacementTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_place_record_routes_and_removes_stale_copy(self):
        opened = record.build_record(merged_advisory(), analysis(review={"tree": "t", "reasons": [REASON]}))
        resolved = dict(opened, review=dict(opened["review"], status="resolved"))
        name = "GHSA-8q59-q68h-6hv4.json"
        record.write_record(resolved, self.out)
        path = record.place_record(opened, self.out)
        self.assertEqual(path, self.out / "review" / name)
        self.assertTrue(path.exists())
        self.assertFalse((self.out / name).exists())
        path = record.place_record(resolved, self.out)
        self.assertEqual(path, self.out / name)
        self.assertFalse((self.out / "review" / name).exists())
        self.assertEqual(record.record_dir(opened, self.out), self.out / "review")
        self.assertEqual(record.record_dir(resolved, self.out), self.out)

    def test_write_index_refuses_both_folder_conflict(self):
        opened = record.build_record(merged_advisory(), analysis(review={"tree": "t", "reasons": [REASON]}))
        other = record.build_record(merged_advisory(id="GHSA-6757-jp84-gxfx", aliases=[]), analysis())
        record.write_record(other, self.out)
        record.place_record(opened, self.out)
        self.assertEqual(record.folder_conflicts(self.out), [])
        index = json.loads(record.write_index(self.out).read_text(encoding="utf-8"))
        self.assertEqual(list(index), ["GHSA-6757-jp84-gxfx"])  # review-only records are not indexed
        record.write_record(dict(opened, review=dict(opened["review"], status="none")), self.out)
        self.assertEqual(record.folder_conflicts(self.out), ["GHSA-8q59-q68h-6hv4"])
        with self.assertRaises(PipelineError) as ctx:
            record.write_index(self.out)
        self.assertEqual(str(ctx.exception), "records in both folders: GHSA-8q59-q68h-6hv4")


if __name__ == "__main__":
    unittest.main()
