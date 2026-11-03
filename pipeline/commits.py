"""Candidate fix commits for an advisory, the checks that reject false ones,
and the library files each commit changes.

Everything here runs against a local clone (see pipeline.repos). Links are
read without trusting their labels: the research found the FIX label is
unreliable, so every commit, pull-request and compare link is a candidate
and the release check decides.
"""

import re
import subprocess

import depscan
from pipeline.repos import PipelineError, git, github_repo_url

_GITHUB = r"https?://(?:www\.)?github\.com/[^/\s]+/[^/\s]+"
COMMIT_RE = re.compile(_GITHUB + r"/commits?/([0-9a-fA-F]{7,40})(?![0-9a-zA-Z])")
PR_RE = re.compile(_GITHUB + r"/pull/(\d+)")
COMPARE_RE = re.compile(_GITHUB + r"/compare/([^\s#?]+)")
_GITHUB_HOST_RE = re.compile(r"^https?://(?:www\.)?github\.com/", re.IGNORECASE)

# Folders an import package may live under, relative to the repo root.
IMPORT_PREFIXES = ("", "src/", "lib/", "lib3/")

# PyPI names whose import folder is spelled differently.
IMPORT_NAMES = {
    "pyyaml": ["yaml"],
    "pillow": ["pil"],
    "beautifulsoup4": ["bs4"],
    "python-dateutil": ["dateutil"],
    "scikit-learn": ["sklearn"],
    "msgpack-python": ["msgpack"],
}

_TEST_DIRS = {"tests", "test", "testing"}
_DOC_BASENAME_RE = re.compile(
    r"^(changes|changelog|history|news|release|readme|authors|contributors|license|licence|copying)",
    re.IGNORECASE,
)
_DOC_EXTENSIONS = {".rst", ".md", ".txt"}
_VERSION_LINE_RE = re.compile(
    r"^[+-]\s*(?:__version__|__version_info__|version_info|version|VERSION|release|__release__)\s*[:=]"
)
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


# ---------------------------------------------------------------------------
# Candidate commits
# ---------------------------------------------------------------------------

def collect_candidates(merged):
    """Every commit the advisory points at, from GIT ranges and links.

    GitHub commit links resolve immediately; pull-request and compare links
    wait for resolve_candidates. Links on other hosts are recorded with
    resolved=False and never resolved (spec: recorded, not resolved).
    """
    candidates = []
    seen = set()

    def add(sha, url, source, resolved, repo):
        key = (sha, url, source)
        if key not in seen:
            seen.add(key)
            candidates.append({"sha": sha, "url": url, "source": source,
                               "resolved": resolved, "repo": repo})

    for rng in merged.get("git_ranges") or []:
        if rng.get("fixed"):
            add(rng["fixed"], None, "git_range", True, github_repo_url(rng.get("repo")))

    for link in merged.get("links") or []:
        url = link.get("url") or ""
        if _GITHUB_HOST_RE.match(url):
            repo = github_repo_url(url)
            match = COMMIT_RE.match(url)
            if match:
                add(match.group(1), url, "commit_link", True, repo)
            elif PR_RE.match(url):
                add(None, url, "pr_link", False, repo)
            elif COMPARE_RE.match(url):
                add(None, url, "compare_link", False, repo)
        else:
            source = _other_host_source(url)
            if source:
                add(None, url, source, False, None)
    return candidates


def _other_host_source(url):
    path = url.split("://", 1)[-1]
    if re.search(r"/commits?/[0-9a-fA-F]{6,40}(?![0-9a-zA-Z])", path):
        return "commit_link"
    if re.search(r"/(?:merge_requests|pulls?)/\d+", path):
        return "pr_link"
    if "/compare/" in path:
        return "compare_link"
    return None


def resolve_candidates(candidates, repo_dir, repo_url=None):
    """Turn PR and compare links into commits, and short SHAs into full ones.

    A PR becomes its merge commit(s), found by message (`Merge pull request
    #N` or `(#N)`); a compare link `a...b` becomes every commit in a..b.
    With `repo_url`, PR and compare links that point at a repository of
    another name (an advisory database's own PR, say) are left unresolved:
    their numbers mean nothing in this clone. Anything the clone cannot
    find stays, or becomes, unresolved.
    """
    resolved = []
    for candidate in candidates:
        url = candidate.get("url") or ""
        source = candidate["source"]
        shas = []
        foreign = (
            repo_url and candidate.get("repo")
            and _repo_name(candidate["repo"]) != _repo_name(repo_url)
        )
        if foreign and source in ("pr_link", "compare_link"):
            resolved.append(dict(candidate))
            continue
        if source == "pr_link" and PR_RE.match(url):
            shas = _commits_for_pr(repo_dir, PR_RE.match(url).group(1))
        elif source == "compare_link" and COMPARE_RE.match(url):
            shas = _commits_for_compare(repo_dir, COMPARE_RE.match(url).group(1))
        elif candidate.get("sha"):
            full = full_sha(repo_dir, candidate["sha"])
            if full:
                shas = [full]
            else:
                resolved.append({**candidate, "resolved": False})
                continue
        if shas:
            for sha in shas:
                resolved.append({**candidate, "sha": sha, "resolved": True})
        else:
            resolved.append(dict(candidate))
    return resolved


def _repo_name(url):
    name = url.rstrip("/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith(".git") else name


def full_sha(repo_dir, rev):
    """The full commit SHA for `rev` in the clone, or None if it isn't there."""
    try:
        return git(repo_dir, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").strip() or None
    except PipelineError:
        return None


def _commits_for_pr(repo_dir, number):
    """Every commit whose message names the PR: the merge commit and its backports."""
    output = git(
        repo_dir, "log", "--all", "--format=%H", "-E",
        f"--grep=Merge pull request #{number}( |$)",
        f"--grep=\\(#{number}\\)",
    )
    return sorted(set(output.split()))


def _commits_for_compare(repo_dir, spec):
    base, _, head = spec.partition("...")
    if not head:
        base, _, head = spec.partition("..")
    if not base or not head:
        return []
    try:
        return git(repo_dir, "rev-list", "--topo-order", f"{base}..{head}").split()
    except PipelineError:
        return []


# ---------------------------------------------------------------------------
# Checks on a commit
# ---------------------------------------------------------------------------

def release_check(repo_dir, sha, fixed_tag, last_vulnerable_tag):
    """Is the commit in the fixed release and not in the last vulnerable one?

    Unchecked (all None) when either tag is unknown; the caller lowers
    confidence instead of guessing.
    """
    if not fixed_tag or not last_vulnerable_tag:
        return {"in_fixed": None, "in_last_vulnerable": None, "checked": False}
    return {
        "in_fixed": _is_ancestor(repo_dir, sha, fixed_tag),
        "in_last_vulnerable": _is_ancestor(repo_dir, sha, last_vulnerable_tag),
        "checked": True,
    }


def _is_ancestor(repo_dir, sha, ref):
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "merge-base", "--is-ancestor", sha, ref],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise PipelineError(f"git merge-base --is-ancestor {sha} {ref} failed:\n{result.stderr.strip()}")


def is_version_bump(repo_dir, sha):
    """True when the commit only touches version strings, changelogs and docs."""
    diff = git(repo_dir, "diff", "--no-color", "--unified=0", f"{sha}^", sha)
    path = None
    doc_file = False
    touched = False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            path = line.split(" b/", 1)[-1]
            doc_file = _is_doc_path(path)
            touched = True
        elif line.startswith(("+++", "---", "@@", "diff ", "index ", "new file", "deleted file",
                              "similarity", "rename ", "old mode", "new mode")):
            continue
        elif line.startswith("Binary files"):
            return False
        elif line.startswith(("+", "-")):
            if doc_file or _VERSION_LINE_RE.match(line):
                continue
            return False
    return touched


def _is_doc_path(path):
    parts = path.split("/")
    if any(part in ("doc", "docs") for part in parts[:-1]):
        return True
    name = parts[-1]
    if _DOC_BASENAME_RE.match(name):
        return True
    return any(name.lower().endswith(ext) for ext in _DOC_EXTENSIONS)


def is_release_bundle(repo_dir, sha):
    """True when a release tag points directly at the commit."""
    tags = git(repo_dir, "tag", "--points-at", sha).split()
    return any(re.search(r"\d", tag) for tag in tags)


def group_backports(repo_dir, shas):
    """Group commits that carry the same patch (backports, cherry-picks)."""
    groups = {}
    order = []
    seen = set()
    for sha in shas:
        if sha in seen:
            continue
        seen.add(sha)
        key = _patch_id(repo_dir, sha) or sha
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(sha)
    return [groups[key] for key in order]


def _patch_id(repo_dir, sha):
    diff = git(repo_dir, "diff", f"{sha}^", sha)
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "patch-id", "--stable"],
        input=diff, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return result.stdout.split()[0] if result.stdout.split() else None


# ---------------------------------------------------------------------------
# Changed library files
# ---------------------------------------------------------------------------

def import_folders(repo_dir, sha, package):
    """Folders holding the package's importable code, e.g. ['lib/yaml', 'lib3/yaml']."""
    wanted = {depscan.normalize_name(package, "PyPI")}
    wanted.update(IMPORT_NAMES.get(depscan.normalize_name(package, "PyPI"), []))
    folders = []
    for rev in (f"{sha}^", sha):
        for path in git(repo_dir, "ls-tree", "-r", "--name-only", rev).splitlines():
            if not path.endswith("/__init__.py"):
                continue
            folder = path[: -len("/__init__.py")]
            parent, _, name = folder.rpartition("/")
            prefix = parent + "/" if parent else ""
            if prefix in IMPORT_PREFIXES and depscan.normalize_name(name, "PyPI") in wanted:
                if folder not in folders:
                    folders.append(folder)
    return folders


def module_for_path(path, folder):
    """Dotted module name of a file under an import folder ('lib3/yaml/x.py' -> 'yaml.x')."""
    package = folder.rsplit("/", 1)[-1]
    rel = path[len(folder) + 1:]
    if rel == "__init__.py":
        return package
    return package + "." + rel[:-3].replace("/", ".")


def _is_test_path(path):
    parts = path.split("/")
    if any(part in _TEST_DIRS for part in parts[:-1]):
        return True
    name = parts[-1]
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def changed_library_files(repo_dir, sha, package):
    """The package's own .py files the commit changes, with before/after text and lines.

    Drops tests, docs, build files and helpers outside the import folder.
    A merge commit is diffed against its first parent.
    """
    folders = import_folders(repo_dir, sha, package)
    files = []
    status = git(repo_dir, "diff", "--name-status", "-M", f"{sha}^", sha)
    for line in status.splitlines():
        parts = line.split("\t")
        if parts[0][:1] in ("R", "C"):
            old_path, path = parts[1], parts[2]
        else:
            old_path = path = parts[1]
        folder = next((f for f in folders if path.startswith(f + "/")), None)
        if folder is None or not path.endswith(".py") or _is_test_path(path):
            continue
        before = "" if parts[0] == "A" else git(repo_dir, "show", f"{sha}^:{old_path}")
        after = "" if parts[0] == "D" else git(repo_dir, "show", f"{sha}:{path}")
        before_lines, after_lines = _changed_lines(repo_dir, sha, old_path, path)
        files.append({
            "path": path,
            "module": module_for_path(path, folder),
            "before": before,
            "after": after,
            "before_lines": before_lines,
            "after_lines": after_lines,
        })
    return files


def _changed_lines(repo_dir, sha, old_path, path):
    diff = git(repo_dir, "diff", "--no-color", "--unified=0", "-M", f"{sha}^", sha, "--", old_path, path)
    before_lines, after_lines = [], []
    for line in diff.splitlines():
        match = _HUNK_RE.match(line)
        if not match:
            continue
        old_start, old_count = int(match.group(1)), int(match.group(2) or 1)
        new_start, new_count = int(match.group(3)), int(match.group(4) or 1)
        before_lines.extend(range(old_start, old_start + old_count))
        after_lines.extend(range(new_start, new_start + new_count))
    return before_lines, after_lines
