"""Unit tests for pipeline.repos: repo discovery, clone cache, tag matching.

Run from the repository root:
    python -m unittest tests.test_repos
"""

import subprocess
import tempfile
import unittest
from pathlib import Path

from pipeline import repos


def run_git(repo_dir, *args):
    subprocess.run(
        ["git", "-C", str(repo_dir), "-c", "user.name=t", "-c", "user.email=t@example.com",
         "-c", "commit.gpgsign=false", *args],
        check=True, capture_output=True, text=True,
    )


def make_repo(root):
    """A throwaway repo: two commits, tags v1.0, pkg-2.0, and both 3.0 and v3.0."""
    repo = Path(root) / "origin"
    repo.mkdir()
    run_git(repo, "init", "-q")
    (repo / "a.txt").write_text("one\n", encoding="utf-8")
    run_git(repo, "add", "a.txt")
    run_git(repo, "commit", "-q", "-m", "first")
    run_git(repo, "tag", "v1.0")
    (repo / "a.txt").write_text("two\n", encoding="utf-8")
    run_git(repo, "commit", "-q", "-am", "second")
    run_git(repo, "tag", "pkg-2.0")
    run_git(repo, "tag", "3.0")
    run_git(repo, "tag", "v3.0")
    return repo


class GitRepoTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = make_repo(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_tag_for_version_tries_patterns_in_order(self):
        self.assertEqual(repos.tag_for_version(self.repo, "pkg", "1.0"), "v1.0")
        self.assertEqual(repos.tag_for_version(self.repo, "pkg", "2.0"), "pkg-2.0")
        # v{v} wins over {v} when both exist
        self.assertEqual(repos.tag_for_version(self.repo, "pkg", "3.0"), "v3.0")

    def test_tag_for_version_none_when_no_pattern_matches(self):
        self.assertIsNone(repos.tag_for_version(self.repo, "pkg", "9.9"))

    def test_git_raises_pipeline_error_with_stderr(self):
        with self.assertRaises(repos.PipelineError) as ctx:
            repos.git(self.repo, "log", "no-such-ref")
        self.assertIn("no-such-ref", str(ctx.exception))
        self.assertEqual(repos.git(self.repo, "tag", "--list", "v1.0").strip(), "v1.0")

    def test_ensure_clone_clones_then_fetches(self):
        cache = self.root / "cache"
        clone = repos.ensure_clone(str(self.repo), cache)
        self.assertTrue((clone / ".git").is_dir())
        self.assertTrue(clone.is_relative_to(cache))
        self.assertIn("v1.0", repos.git(clone, "tag").split())

        run_git(self.repo, "tag", "v4.0")
        again = repos.ensure_clone(str(self.repo), cache)
        self.assertEqual(again, clone)
        self.assertIn("v4.0", repos.git(clone, "tag").split())


class FindRepoUrlTest(unittest.TestCase):
    def test_repo_url_prefers_git_ranges_over_links(self):
        merged = {
            "package": "pyyaml",
            "git_ranges": [{"repo": "https://github.com/yaml/pyyaml.git", "introduced": "0", "fixed": "abc"}],
            "links": [{"type": "PACKAGE", "url": "https://github.com/other/repo"}],
        }
        self.assertEqual(repos.find_repo_url(merged), "https://github.com/yaml/pyyaml")

        merged["git_ranges"] = []
        self.assertEqual(repos.find_repo_url(merged), "https://github.com/other/repo")

        # only PACKAGE/REPO typed links count, and the URL is reduced to owner/repo
        merged["links"] = [
            {"type": "WEB", "url": "https://github.com/yaml/pyyaml/issues/420"},
            {"type": "PACKAGE", "url": "https://github.com/psf/requests/tree/main/"},
        ]
        self.assertEqual(repos.find_repo_url(merged), "https://github.com/psf/requests")

    def test_repo_url_falls_back_to_injected_pypi_urls(self):
        merged = {"package": "idna", "git_ranges": [], "links": []}
        calls = []

        def fake_fetch(package):
            calls.append(package)
            return ["https://pypi.org/project/idna", "https://github.com/kjd/idna"]

        self.assertEqual(repos.find_repo_url(merged, fetch=fake_fetch), "https://github.com/kjd/idna")
        self.assertEqual(calls, ["idna"])

        self.assertIsNone(repos.find_repo_url(merged, fetch=lambda package: ["https://idna.example.org"]))


if __name__ == "__main__":
    unittest.main()
