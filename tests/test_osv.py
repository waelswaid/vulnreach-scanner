"""Unit tests for pipeline.osv: loading and merging OSV advisories.

Run from the repository root:
    python -m unittest tests.test_osv
"""

import json
import tempfile
import unittest
from pathlib import Path

from pipeline import osv


def make_advisory(vuln_id, package, aliases=(), modified="2024-01-01T00:00:00Z",
                  ranges=None, versions=None, references=None, summary="", details="",
                  extra_affected=None):
    """A minimal OSV advisory dict in the shape of the PyPI export."""
    affected = [
        {
            "package": {"name": package, "ecosystem": "PyPI"},
            "ranges": ranges or [],
            "versions": versions or [],
        }
    ]
    if extra_affected:
        affected.extend(extra_affected)
    return {
        "id": vuln_id,
        "aliases": list(aliases),
        "modified": modified,
        "summary": summary,
        "details": details,
        "affected": affected,
        "references": references or [],
    }


class LoadMergedTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.export = Path(self._tmp.name) / "export"
        self.export.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def write_export(self, advisories):
        """Write each advisory to export/<id>.json, as OSV's all.zip extracts."""
        for advisory in advisories:
            path = self.export / f"{advisory['id']}.json"
            path.write_text(json.dumps(advisory), encoding="utf-8")
        return self.export

    def test_aliased_advisories_merge_into_one(self):
        export = self.write_export([
            make_advisory("GHSA-aaaa-bbbb-cccc", "pyyaml",
                          aliases=["CVE-2020-0001", "PYSEC-2020-1"],
                          summary="Bad input", details="Long story."),
            make_advisory("PYSEC-2020-1", "pyyaml",
                          aliases=["CVE-2020-0001", "GHSA-aaaa-bbbb-cccc"]),
        ])
        merged = osv.load_merged(export)
        self.assertEqual(list(merged), ["GHSA-aaaa-bbbb-cccc"])
        entry = merged["GHSA-aaaa-bbbb-cccc"]
        self.assertEqual(entry["id"], "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(entry["aliases"], ["CVE-2020-0001", "PYSEC-2020-1"])
        self.assertEqual(entry["package"], "pyyaml")
        self.assertEqual(entry["ecosystem"], "PyPI")
        self.assertEqual(entry["summary_text"], "Bad input\n\nLong story.")
        self.assertEqual(sorted(a["id"] for a in entry["raw"]),
                         ["GHSA-aaaa-bbbb-cccc", "PYSEC-2020-1"])

    def test_package_filter_uses_normalized_names(self):
        export = self.write_export([
            make_advisory("GHSA-1111-2222-3333", "typing_extensions"),
            make_advisory("GHSA-4444-5555-6666", "requests"),
        ])
        merged = osv.load_merged(export, packages={"typing-extensions"})
        self.assertEqual(list(merged), ["GHSA-1111-2222-3333"])
        self.assertEqual(merged["GHSA-1111-2222-3333"]["package"], "typing-extensions")
        self.assertEqual(osv.load_merged(export, packages={"Typing.Extensions"}).keys(),
                         merged.keys())
        self.assertEqual(osv.load_merged(export, packages={"nothing"}), {})

    def test_git_ranges_and_links_collected(self):
        git_range = {
            "type": "GIT",
            "repo": "https://github.com/yaml/pyyaml",
            "events": [{"introduced": "0"}, {"fixed": "a001f2782501ad2d24986959f0239a354675f9dc"}],
        }
        eco_range = {"type": "ECOSYSTEM", "events": [{"introduced": "5.1"}, {"fixed": "5.4"}]}
        links = [
            {"type": "WEB", "url": "https://github.com/yaml/pyyaml/issues/420"},
            {"type": "FIX", "url": "https://github.com/yaml/pyyaml/commit/a001f27"},
        ]
        export = self.write_export([
            make_advisory("GHSA-aaaa-bbbb-cccc", "pyyaml", aliases=["PYSEC-2021-1"],
                          ranges=[git_range, eco_range], versions=["5.3", "5.1", "5.2"],
                          references=links),
            make_advisory("PYSEC-2021-1", "pyyaml", aliases=["GHSA-aaaa-bbbb-cccc"],
                          ranges=[eco_range], versions=["5.3.1", "5.1"],
                          references=[links[0], {"type": "WEB", "url": "https://example.org/x"}]),
        ])
        entry = osv.load_merged(export)["GHSA-aaaa-bbbb-cccc"]
        self.assertEqual(entry["git_ranges"], [{
            "repo": "https://github.com/yaml/pyyaml",
            "introduced": "0",
            "fixed": "a001f2782501ad2d24986959f0239a354675f9dc",
        }])
        self.assertEqual(entry["links"], links + [{"type": "WEB", "url": "https://example.org/x"}])
        self.assertEqual(entry["affected_versions"], ["5.1", "5.2", "5.3", "5.3.1"])
        self.assertEqual(entry["fixed_versions"], ["5.4"])

    def test_modified_is_max_across_sources(self):
        export = self.write_export([
            make_advisory("GHSA-aaaa-bbbb-cccc", "pyyaml", aliases=["PYSEC-2021-1"],
                          modified="2024-10-25T21:23:11Z"),
            make_advisory("PYSEC-2021-1", "pyyaml", aliases=["GHSA-aaaa-bbbb-cccc"],
                          modified="2026-02-04T03:33:10Z"),
        ])
        entry = osv.load_merged(export)["GHSA-aaaa-bbbb-cccc"]
        self.assertEqual(entry["modified"], "2026-02-04T03:33:10Z")

    def test_multi_package_advisory_gets_one_entry_per_package(self):
        pil_affected = {
            "package": {"name": "PIL", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.8"}]}],
            "versions": ["1.1.7"],
        }
        export = self.write_export([
            make_advisory(
                "GHSA-aaaa-bbbb-cccc", "pillow", summary="Shared summary",
                ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.0.1"}]}],
                versions=["9.0.0"], extra_affected=[pil_affected],
            ),
        ])
        merged = osv.load_merged(export)
        self.assertEqual(sorted(merged), ["GHSA-aaaa-bbbb-cccc:pil", "GHSA-aaaa-bbbb-cccc:pillow"])
        pillow = merged["GHSA-aaaa-bbbb-cccc:pillow"]
        pil = merged["GHSA-aaaa-bbbb-cccc:pil"]
        self.assertEqual(pillow["id"], "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(pillow["package"], "pillow")
        self.assertEqual(pillow["fixed_versions"], ["9.0.1"])
        self.assertEqual(pillow["affected_versions"], ["9.0.0"])
        self.assertEqual(pil["package"], "pil")
        self.assertEqual(pil["fixed_versions"], ["1.1.8"])
        self.assertEqual(pil["affected_versions"], ["1.1.7"])
        self.assertEqual(pil["summary_text"], pillow["summary_text"])


if __name__ == "__main__":
    unittest.main()
