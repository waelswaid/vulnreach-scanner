"""Tests for pipeline.run: the driver, review placement and freshness.

Run from the repository root:
    python -m unittest tests.test_run
"""

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pipeline import entrypoints, functions, osv, record, repos, run, verify
from pipeline.repos import PipelineError
from tests.test_commits import head, write
from tests.test_repos import run_git

ID = "GHSA-aaaa-bbbb-cccc"
OTHER_ID = "GHSA-dddd-eeee-ffff"
REPO_URL = "https://github.com/acme/pkg"

CORE_BEFORE = "def parse(text):\n    return eval(text)\n"
CORE_AFTER = "def parse(text):\n    return int(text)\n"

REASON = {"item": "pkg.core.parse", "kind": "no_reference", "file": "src/pkg/core.py",
          "references": [], "dead_ends": []}
ENTRY = {"name": "pkg.parse", "defined_as": "pkg.core.parse", "confidence": "high",
         "path": ["pkg.parse"]}


def advisory(sha, advisory_id=ID, **overrides):
    base = {
        "id": advisory_id,
        "aliases": ["CVE-2026-0001"] if advisory_id == ID else ["CVE-2026-0002"],
        "package": "pkg",
        "ecosystem": "PyPI",
        "modified": "2026-10-01T00:00:00Z",
        "summary_text": "Code injection in pkg",
        "links": [
            {"type": "PACKAGE", "url": REPO_URL},
            {"type": "FIX", "url": f"{REPO_URL}/commit/{sha}"},
        ],
        "git_ranges": [],
        "affected_versions": ["1.0"],
        "fixed_versions": ["1.1"],
        "raw": [],
    }
    base.update(overrides)
    return base


class RunTest(unittest.TestCase):
    """v1.0 (c1) --- c2 "fix parse" --- c3 "Release 1.1" [v1.1]"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.repo = root / "repo"
        self.repo.mkdir()
        self.cache = root / "cache"
        self.out = root / "vulnfuncs"
        self.overrides_path = root / "overrides.json"
        self.overrides_path.write_text("{}\n", encoding="utf-8")
        r = self.repo
        run_git(r, "init", "-q", "-b", "master")
        write(r, "src/pkg/__init__.py", '__version__ = "1.0"\n')
        write(r, "src/pkg/core.py", CORE_BEFORE)
        write(r, "setup.py", 'version = "1.0"\n')
        write(r, "CHANGES.rst", "1.0\n")
        run_git(r, "add", ".")
        run_git(r, "commit", "-q", "-m", "initial")
        run_git(r, "tag", "v1.0")
        self.c1 = head(r)

        write(r, "src/pkg/core.py", CORE_AFTER)
        run_git(r, "commit", "-q", "-am", "fix parse")
        self.c2 = head(r)

        write(r, "setup.py", 'version = "1.1"\n')
        write(r, "CHANGES.rst", "1.1\n- fix parse\n\n1.0\n")
        run_git(r, "commit", "-q", "-am", "Release 1.1")
        run_git(r, "tag", "v1.1")
        self.c3 = head(r)

        self.reasons = []
        self.walk_calls = []
        self.found = [{"name": "pkg.core.parse", "kind": "function", "change": "modified",
                       "evidence": ["body changed"]}]
        self._patch(repos, "ensure_clone", lambda url, cache_dir: self.repo)
        self._patch(functions, "changed_functions", self.fake_changed_functions)
        self._patch(verify, "verify_names", lambda *args: [">=1.0, <1.1"])
        self._patch(entrypoints, "sources_at",
                    lambda repo_dir, rev, package: [{"module": "pkg", "rev": rev}])
        self._patch(entrypoints, "walk", self.fake_walk)

    def _patch(self, target, name, value):
        patcher = mock.patch.object(target, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_changed_functions(self, before, after, before_lines, after_lines, module):
        found = self.found if module == "pkg.core" else []
        return {"vulnerable": [dict(v) for v in found], "added": [], "cosmetic": [], "notes": []}

    def fake_walk(self, sources, import_name, vulnerable):
        self.walk_calls.append((sources, import_name, vulnerable))
        return {"entry_points": [dict(ENTRY)], "reasons": [dict(r) for r in self.reasons],
                "notes": ["walk note"]}

    def process(self, merged, overrides=None):
        return run.process_advisory(merged, self.cache, self.out, overrides or {})

    def run_main(self, *args, merged=None):
        advisories = merged or [advisory(self.c2)]
        loaded = {m["id"]: m for m in advisories}
        argv = ["--export", "unused", "--cache", str(self.cache), "--out", str(self.out),
                "--overrides", str(self.overrides_path), *args]
        stdout = io.StringIO()
        with mock.patch.object(osv, "load_merged", lambda export_dir, packages=None: loaded), \
                contextlib.redirect_stdout(stdout):
            code = run.main(argv)
        self.assertEqual(code, 0)
        return stdout.getvalue()

    def read(self, folder, advisory_id=ID):
        return json.loads((folder / f"{advisory_id}.json").read_text(encoding="utf-8"))

    # -- tests ---------------------------------------------------------------

    def test_end_to_end_found_record_in_main_folder(self):
        merged = advisory(self.c2[:10])
        merged["links"].append(
            {"type": "WEB", "url": "https://github.com/github/advisory-database/pull/123"})
        rec = self.process(merged)

        self.assertEqual(rec["status"], "found")
        self.assertEqual(rec["repo"], REPO_URL)
        self.assertEqual(self.read(self.out), rec)
        self.assertFalse((self.out / "review" / f"{ID}.json").exists())
        self.assertEqual(rec["fix_commits"], [
            {"sha": self.c2, "source": "commit_link", "in_fixed_release": True, "bundle": False}])
        self.assertEqual(rec["rejected_commits"], [
            {"sha": None, "url": "https://github.com/github/advisory-database/pull/123",
             "source": "pr_link", "reason": "unresolved"}])
        self.assertEqual([(v["name"], v["file"], v["confidence"]) for v in rec["vulnerable"]],
                         [("pkg.core.parse", "src/pkg/core.py", "high")])
        self.assertEqual(rec["entry_points"], [ENTRY])
        self.assertEqual(rec["names_verified_for"], [">=1.0, <1.1"])
        self.assertIn("walk note", rec["notes"])
        self.assertEqual(rec["review"]["status"], "none")
        self.assertEqual(rec["review"]["tree"], self.c1)
        sources, import_name, vulnerable = self.walk_calls[0]
        self.assertEqual(sources, [{"module": "pkg", "rev": self.c1}])
        self.assertEqual(import_name, "pkg")
        self.assertEqual(vulnerable[0]["name"], "pkg.core.parse")

    def test_reasons_route_record_to_review_folder(self):
        self.reasons = [REASON]
        rec = self.process(advisory(self.c2))
        self.assertEqual(rec["review"]["status"], "open")
        self.assertEqual(rec["review"]["reasons"], [REASON])
        self.assertEqual(self.read(self.out / "review"), rec)
        self.assertFalse((self.out / f"{ID}.json").exists())

    def test_move_between_folders_removes_stale_copy(self):
        self.reasons = [REASON]
        self.process(advisory(self.c2))
        self.assertTrue((self.out / "review" / f"{ID}.json").exists())
        self.reasons = []
        self.process(advisory(self.c2))
        self.assertTrue((self.out / f"{ID}.json").exists())
        self.assertFalse((self.out / "review" / f"{ID}.json").exists())

    def test_both_folder_leftover_is_reprocessed(self):
        self.process(advisory(self.c2))
        (self.out / "review").mkdir(parents=True, exist_ok=True)
        shutil.copy(self.out / f"{ID}.json", self.out / "review" / f"{ID}.json")
        self.assertIsNone(run.existing_record(self.out, ID))
        self.walk_calls.clear()

        output = self.run_main("--advisory", ID)
        self.assertEqual(len(self.walk_calls), 1)
        self.assertEqual(record.folder_conflicts(self.out), [])
        self.assertIn(f"{ID}  found  main", output)

    def test_freshness_skips_unchanged_and_override_change_reprocesses(self):
        self.run_main("--all")
        self.assertEqual(len(self.walk_calls), 1)
        merged = advisory(self.c2)
        self.assertTrue(run.is_fresh(run.existing_record(self.out, ID), merged, None))

        output = self.run_main("--all")
        self.assertEqual(len(self.walk_calls), 1)
        self.assertIn(f"{ID}  found  main", output)
        self.assertIn("in review: 0", output)

        spec = {"note": "checked by hand"}
        self.overrides_path.write_text(json.dumps({ID: spec}), encoding="utf-8")
        self.assertFalse(run.is_fresh(run.existing_record(self.out, ID), merged, spec))
        self.run_main("--all")
        self.assertEqual(len(self.walk_calls), 2)
        rec = self.read(self.out)
        self.assertIn("checked by hand", rec["notes"])
        self.assertEqual(rec["overrides_fingerprint"], record.overrides_fingerprint(spec))

        changed = advisory(self.c2, modified="2026-10-20T00:00:00Z")
        self.assertFalse(run.is_fresh(rec, changed, spec))

    def test_force_reprocesses(self):
        self.run_main("--all")
        self.run_main("--all", "--force")
        self.assertEqual(len(self.walk_calls), 2)

    def test_version_bump_only_candidate_gives_unknown(self):
        rec = self.process(advisory(self.c3))
        self.assertEqual(rec["status"], "unknown")
        self.assertEqual(rec["fix_commits"], [])
        self.assertEqual([c["reason"] for c in rec["rejected_commits"]], ["version bump only"])
        self.assertIn("no usable fix commit", rec["notes"])
        self.assertTrue((self.out / f"{ID}.json").exists())

    def test_no_repo_gives_unknown_with_note(self):
        with mock.patch.object(repos, "find_repo_url", lambda merged: None):
            rec = self.process(advisory(self.c2, links=[]))
        self.assertEqual(rec["status"], "unknown")
        self.assertIsNone(rec["repo"])
        self.assertEqual(rec["notes"], ["no GitHub repository found"])
        self.assertEqual(rec["review"]["status"], "none")
        self.assertEqual(self.read(self.out), rec)

    def test_bundle_commit_caps_confidence_medium(self):
        run_git(self.repo, "tag", "v1.1rc1", self.c2)
        rec = self.process(advisory(self.c2))
        self.assertEqual(rec["fix_commits"][0]["bundle"], True)
        self.assertEqual(rec["fix_commits"][0]["in_fixed_release"], True)
        self.assertEqual(rec["vulnerable"][0]["confidence"], "medium")

    def test_not_code_when_only_non_library_files_change(self):
        r = self.repo
        write(r, "data.pem", "-----BEGIN CERTIFICATE-----\nnew\n")
        write(r, "src/pkg/__init__.py", '__version__ = "1.2"\n')
        run_git(r, "add", ".")
        run_git(r, "commit", "-q", "-m", "update bundled certificate")
        fix = head(r)
        write(r, "CHANGES.rst", "1.2\n")
        run_git(r, "commit", "-q", "-am", "Release 1.2")
        run_git(r, "tag", "v1.2")
        self.found = []
        rec = self.process(advisory(fix, affected_versions=["1.1"], fixed_versions=["1.2"]))
        self.assertEqual(rec["status"], "not_code")
        self.assertEqual(rec["vulnerable"], [])
        self.assertEqual(rec["entry_points"], [])
        self.assertEqual(self.walk_calls, [])

    def test_pipeline_error_becomes_unknown_record(self):
        def boom(*args):
            raise PipelineError("boom")
        with mock.patch.object(functions, "changed_functions", boom):
            rec = self.process(advisory(self.c2))
        self.assertEqual(rec["status"], "unknown")
        self.assertEqual(rec["notes"], ["pipeline error: boom"])
        self.assertEqual(rec["overrides_fingerprint"], None)
        self.assertEqual(self.read(self.out), rec)

    def test_index_rebuilt_and_excludes_review(self):
        self.reasons = [REASON]
        self.process(advisory(self.c2, advisory_id=OTHER_ID))
        self.reasons = []
        output = self.run_main("--advisory", ID,
                               merged=[advisory(self.c2), advisory(self.c2, advisory_id=OTHER_ID)])
        index = json.loads((self.out / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(index, {ID: ID, "CVE-2026-0001": ID})
        self.assertNotIn(OTHER_ID, output)
        self.assertIn("in review: 0", output)


if __name__ == "__main__":
    unittest.main()
