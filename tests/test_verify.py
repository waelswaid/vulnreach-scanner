"""Unit tests for pipeline.verify: do the vulnerable names exist across affected versions?

Run from the repository root:
    python -m unittest tests.test_verify
"""

import tempfile
import unittest
from pathlib import Path

from pipeline import verify
from tests.test_repos import run_git


class CollectNamesTest(unittest.TestCase):
    def test_collect_names_covers_functions_methods_classes(self):
        source = (
            "class Cls:\n"
            "    def meth(self):\n"
            "        pass\n"
            "\n"
            "def func():\n"
            "    def inner():\n"
            "        pass\n"
            "    return inner\n"
        )
        self.assertEqual(
            verify.collect_names(source, "pkg.mod"),
            {"pkg.mod.Cls", "pkg.mod.Cls.meth", "pkg.mod.func", "pkg.mod.func.inner"},
        )

    def test_collect_names_unparseable_is_empty(self):
        self.assertEqual(verify.collect_names("print 'py2'\n", "pkg.mod"), set())


class RangesFromSeriesTest(unittest.TestCase):
    def test_contiguous_verified_series_become_one_range(self):
        self.assertEqual(verify.ranges_from_series([("5.1", True), ("5.2", True), ("5.3", True)]),
                         [">=5.1, <5.4"])

    def test_gap_splits_ranges(self):
        self.assertEqual(verify.ranges_from_series([("5.1", True), ("5.2", False), ("5.3", True)]),
                         [">=5.1, <5.2", ">=5.3, <5.4"])

    def test_unmatched_tag_series_excluded(self):
        # None = no tag matched the series; it is neither verified nor a confirmed miss.
        self.assertEqual(verify.ranges_from_series([("1.9", None), ("1.10", True), ("1.11", True), ("2.0", None)]),
                         [">=1.10, <1.12"])
        self.assertEqual(verify.ranges_from_series([("1.0", None)]), [])


def write(repo, rel, text):
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class VerifyNamesTest(unittest.TestCase):
    """v1.0 and v1.0.1 define old() and keep(); v1.1 drops old(); 1.2 has no tag."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()
        r = self.repo
        run_git(r, "init", "-q", "-b", "master")
        write(r, "src/pkg/__init__.py", "")
        write(r, "src/pkg/mod.py", "def old():\n    pass\n\n\ndef keep():\n    pass\n")
        run_git(r, "add", ".")
        run_git(r, "commit", "-q", "-m", "1.0")
        run_git(r, "tag", "v1.0")
        write(r, "README.md", "docs\n")
        run_git(r, "add", ".")
        run_git(r, "commit", "-q", "-m", "1.0.1")
        run_git(r, "tag", "v1.0.1")
        write(r, "src/pkg/mod.py", "def keep():\n    pass\n")
        run_git(r, "commit", "-q", "-am", "1.1")
        run_git(r, "tag", "v1.1")

    def tearDown(self):
        self._tmp.cleanup()

    def test_verify_names_against_two_tags(self):
        affected = ["1.0", "1.0.1", "1.1", "1.2"]
        self.assertEqual(verify.verify_names(self.repo, "pkg", ["pkg.mod.keep"], affected),
                         [">=1.0, <1.2"])
        self.assertEqual(verify.verify_names(self.repo, "pkg", ["pkg.mod.old"], affected),
                         [">=1.0, <1.1"])
        self.assertEqual(verify.verify_names(self.repo, "pkg", ["pkg.mod", "pkg.mod.keep"], affected),
                         [">=1.0, <1.2"])
        self.assertEqual(verify.verify_names(self.repo, "pkg", ["pkg.other.keep"], affected), [])


if __name__ == "__main__":
    unittest.main()
