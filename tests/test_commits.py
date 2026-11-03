"""Unit tests for pipeline.commits: candidate commits, release check, filters.

Run from the repository root:
    python -m unittest tests.test_commits
"""

import tempfile
import unittest
from pathlib import Path

from pipeline import commits
from tests.test_repos import run_git


def write(repo, rel, text):
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def head(repo):
    import subprocess
    return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()


MOD_BEFORE = "def f():\n    return 1\n"
MOD_AFTER = "def f():\n    return 2\n"


class CommitsRepoTest(unittest.TestCase):
    """A repo with a release tag, a code fix (#7), a version bump release, and a backport.

    v1.0 (c1) --- c2 "fix the bug (#7)" --- c3 "Release 1.1" [v1.1]      (master)
         \\--- c4 cherry-pick of c2                                        (maint)
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()
        r = self.repo
        run_git(r, "init", "-q", "-b", "master")
        write(r, "src/pkg/__init__.py", "")
        write(r, "src/pkg/mod.py", MOD_BEFORE)
        write(r, "src/pkg/old.py", "def gone():\n    pass\n")
        write(r, "src/pkg/tests/test_inner.py", "def test_inner():\n    pass\n")
        write(r, "tests/test_mod.py", "def test_f():\n    assert True\n")
        write(r, "CHANGES.rst", "1.0\n---\n")
        write(r, "setup.py", 'version = "1.0"\n')
        run_git(r, "add", ".")
        run_git(r, "commit", "-q", "-m", "initial")
        run_git(r, "tag", "v1.0")
        self.c1 = head(r)

        write(r, "src/pkg/mod.py", MOD_AFTER)
        (r / "src/pkg/old.py").unlink()
        write(r, "src/pkg/tests/test_inner.py", "def test_inner():\n    assert 2\n")
        write(r, "tests/test_mod.py", "def test_f():\n    assert f() == 2\n")
        write(r, "docs/index.rst", "Docs\n")
        run_git(r, "add", "-A")
        run_git(r, "commit", "-q", "-m", "fix the bug (#7)")
        self.c2 = head(r)

        write(r, "setup.py", 'version = "1.1"\n')
        write(r, "CHANGES.rst", "1.1\n---\n- fix the bug\n\n1.0\n---\n")
        run_git(r, "commit", "-q", "-am", "Release 1.1")
        run_git(r, "tag", "v1.1")
        self.c3 = head(r)

        # The branch must diverge before the cherry-pick: a pick onto the same
        # parent with the same author date reproduces c2's hash exactly.
        run_git(r, "checkout", "-q", "-b", "maint", "v1.0")
        write(r, "MAINT.txt", "maintenance branch\n")
        run_git(r, "add", "MAINT.txt")
        run_git(r, "commit", "-q", "-m", "start maint branch")
        run_git(r, "cherry-pick", self.c2)
        self.c4 = head(r)
        assert self.c4 != self.c2
        run_git(r, "checkout", "-q", "master")

    def tearDown(self):
        self._tmp.cleanup()

    def test_collects_candidates_from_ranges_and_links(self):
        merged = {
            "git_ranges": [{"repo": "https://github.com/o/r", "introduced": "0", "fixed": self.c2}],
            "links": [
                {"type": "WEB", "url": f"https://github.com/o/r/commit/{self.c3}"},
                {"type": "WEB", "url": "https://github.com/o/r/pull/7"},
                {"type": "WEB", "url": "https://github.com/o/r/compare/v1.0...v1.1"},
                {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-0001"},
                {"type": "PACKAGE", "url": "https://github.com/o/r"},
            ],
        }
        repo = "https://github.com/o/r"
        self.assertEqual(commits.collect_candidates(merged), [
            {"sha": self.c2, "url": None, "source": "git_range", "resolved": True, "repo": repo},
            {"sha": self.c3, "url": f"https://github.com/o/r/commit/{self.c3}",
             "source": "commit_link", "resolved": True, "repo": repo},
            {"sha": None, "url": "https://github.com/o/r/pull/7", "source": "pr_link",
             "resolved": False, "repo": repo},
            {"sha": None, "url": "https://github.com/o/r/compare/v1.0...v1.1",
             "source": "compare_link", "resolved": False, "repo": repo},
        ])

    def test_non_github_link_recorded_unresolved(self):
        merged = {"git_ranges": [], "links": [
            {"type": "FIX", "url": "https://gitlab.com/o/r/-/commit/abc123"},
            {"type": "WEB", "url": "https://gitlab.com/o/r/-/merge_requests/5"},
        ]}
        self.assertEqual(commits.collect_candidates(merged), [
            {"sha": None, "url": "https://gitlab.com/o/r/-/commit/abc123",
             "source": "commit_link", "resolved": False, "repo": None},
            {"sha": None, "url": "https://gitlab.com/o/r/-/merge_requests/5",
             "source": "pr_link", "resolved": False, "repo": None},
        ])

    def test_pr_link_in_another_repo_not_resolved(self):
        # An advisory often links the advisory database's own PR; its number
        # must not be looked up in the package's history.
        foreign = {"sha": None, "url": "https://github.com/github/advisory-database/pull/7",
                   "source": "pr_link", "resolved": False,
                   "repo": "https://github.com/github/advisory-database"}
        own = {"sha": None, "url": "https://github.com/o/r/pull/7", "source": "pr_link",
               "resolved": False, "repo": "https://github.com/o/r"}
        resolved = commits.resolve_candidates([foreign, own], self.repo, repo_url="https://github.com/o/r")
        self.assertEqual([(c["resolved"], c["sha"]) for c in resolved],
                         [(False, None)] + [(True, sha) for sha in sorted([self.c2, self.c4])])
        # the owner may differ (renamed organisations); only the repo name must match
        renamed = dict(own, url="https://github.com/old-org/r/pull/7", repo="https://github.com/old-org/r")
        self.assertTrue(all(c["resolved"] for c in
                            commits.resolve_candidates([renamed], self.repo, repo_url="https://github.com/o/r")))

    def test_resolve_pr_and_compare_links(self):
        candidates = [
            {"sha": None, "url": "https://github.com/o/r/pull/7", "source": "pr_link", "resolved": False},
            {"sha": None, "url": "https://github.com/o/r/compare/v1.0...v1.1",
             "source": "compare_link", "resolved": False},
            {"sha": None, "url": "https://github.com/o/r/pull/999", "source": "pr_link", "resolved": False},
            {"sha": self.c2[:10], "url": "https://github.com/o/r/commit/" + self.c2[:10],
             "source": "commit_link", "resolved": True},
            {"sha": "0" * 40, "url": "https://github.com/fork/r/commit/" + "0" * 40,
             "source": "commit_link", "resolved": True},
        ]
        resolved = commits.resolve_candidates(candidates, self.repo)
        # PR #7 resolves to its commit and the backport that carries "(#7)".
        self.assertEqual(
            [(c["sha"], c["source"], c["resolved"]) for c in resolved],
            [(sha, "pr_link", True) for sha in sorted([self.c2, self.c4])] + [
                (self.c3, "compare_link", True),
                (self.c2, "compare_link", True),
                (None, "pr_link", False),
                (self.c2, "commit_link", True),
                ("0" * 40, "commit_link", False),
            ],
        )

    def test_release_check_ancestor_logic(self):
        self.assertEqual(commits.release_check(self.repo, self.c2, "v1.1", "v1.0"),
                         {"in_fixed": True, "in_last_vulnerable": False, "checked": True})
        self.assertEqual(commits.release_check(self.repo, self.c1, "v1.1", "v1.0"),
                         {"in_fixed": True, "in_last_vulnerable": True, "checked": True})
        self.assertEqual(commits.release_check(self.repo, self.c4, "v1.1", "v1.0"),
                         {"in_fixed": False, "in_last_vulnerable": False, "checked": True})

    def test_release_check_unchecked_without_tags(self):
        unchecked = {"in_fixed": None, "in_last_vulnerable": None, "checked": False}
        self.assertEqual(commits.release_check(self.repo, self.c2, None, "v1.0"), unchecked)
        self.assertEqual(commits.release_check(self.repo, self.c2, "v1.1", None), unchecked)

    def test_version_bump_detected(self):
        self.assertTrue(commits.is_version_bump(self.repo, self.c3))
        self.assertFalse(commits.is_version_bump(self.repo, self.c2))

    def test_release_bundle_detected_by_tag(self):
        self.assertTrue(commits.is_release_bundle(self.repo, self.c3))
        self.assertFalse(commits.is_release_bundle(self.repo, self.c2))

    def test_backports_grouped_by_patch_id(self):
        self.assertEqual(commits.group_backports(self.repo, [self.c2, self.c3, self.c4]),
                         [[self.c2, self.c4], [self.c3]])
        # the same commit reached through two links is listed once
        self.assertEqual(commits.group_backports(self.repo, [self.c2, self.c3, self.c4, self.c2]),
                         [[self.c2, self.c4], [self.c3]])

    def test_changed_library_files_filters_and_maps_modules(self):
        files = commits.changed_library_files(self.repo, self.c2, "pkg")
        self.assertEqual([f["path"] for f in files], ["src/pkg/mod.py", "src/pkg/old.py"])
        self.assertEqual([f["module"] for f in files], ["pkg.mod", "pkg.old"])
        self.assertEqual(files[1]["after"], "")
        self.assertEqual(files[1]["after_lines"], [])
        self.assertEqual(files[1]["before_lines"], [1, 2])

    def test_changed_lines_match_diff(self):
        mod = commits.changed_library_files(self.repo, self.c2, "pkg")[0]
        self.assertEqual(mod["before"], MOD_BEFORE)
        self.assertEqual(mod["after"], MOD_AFTER)
        self.assertEqual(mod["before_lines"], [2])
        self.assertEqual(mod["after_lines"], [2])


class ImportFolderTest(unittest.TestCase):
    def test_module_name_from_path(self):
        self.assertEqual(commits.module_for_path("lib3/yaml/constructor.py", "lib3/yaml"), "yaml.constructor")
        self.assertEqual(commits.module_for_path("src/jinja2/__init__.py", "src/jinja2"), "jinja2")
        self.assertEqual(commits.module_for_path("requests/sessions.py", "requests"), "requests.sessions")


if __name__ == "__main__":
    unittest.main()
