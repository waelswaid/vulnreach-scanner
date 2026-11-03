"""Find, clone and query the upstream repository for an advisory.

Local clones are used instead of the GitHub API: the API is rate-limited and
the pipeline needs the full pre-fix source anyway. Developer tool: uses the
network and the `git` CLI. Standard library only.
"""

import json
import re
import subprocess
import urllib.request
from pathlib import Path

import depscan

PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"

# Tag spellings tried for a version, in order.
TAG_PATTERNS = ("v{version}", "{version}", "{package}-{version}")

_GITHUB_RE = re.compile(r"^https?://(?:www\.)?github\.com/([^/\s]+)/([^/\s#?]+)", re.IGNORECASE)


class PipelineError(Exception):
    """A pipeline step could not complete; the message says why."""


def git(repo_dir, *args):
    """Run `git -C repo_dir args...` and return stdout; raise PipelineError on failure."""
    result = subprocess.run(
        ["git", "-C", str(repo_dir), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if result.returncode != 0:
        raise PipelineError(
            f"git {' '.join(args)} failed in {repo_dir}:\n{result.stderr.strip()}"
        )
    return result.stdout


def github_repo_url(url):
    """Canonical https://github.com/<owner>/<repo> for any GitHub URL, else None."""
    match = _GITHUB_RE.match(url or "")
    if not match:
        return None
    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"https://github.com/{owner}/{repo}"


def fetch_pypi_urls(package):
    """Project URLs from PyPI's JSON API (network)."""
    with urllib.request.urlopen(PYPI_JSON_URL.format(package=package)) as response:
        info = json.loads(response.read().decode("utf-8")).get("info") or {}
    urls = [info.get("home_page") or ""]
    urls.extend((info.get("project_urls") or {}).values())
    return [u for u in urls if u]


def find_repo_url(merged, fetch=fetch_pypi_urls):
    """The advisory's GitHub repository, or None.

    Precedence: GIT version ranges, then a PACKAGE/REPO-typed GitHub link,
    then the package's PyPI project URLs (via `fetch`).
    """
    for rng in merged.get("git_ranges") or []:
        url = github_repo_url(rng.get("repo"))
        if url:
            return url
    for link in merged.get("links") or []:
        if link.get("type") in ("PACKAGE", "REPO"):
            url = github_repo_url(link.get("url"))
            if url:
                return url
    for candidate in fetch(merged["package"]):
        url = github_repo_url(candidate)
        if url:
            return url
    return None


def clone_dir_name(url):
    """Cache directory name for a repo URL: the last two path parts, joined by '__'."""
    parts = [p for p in re.split(r"[/\\]+", url.rstrip("/\\")) if p]
    name = "__".join(parts[-2:])
    if name.endswith(".git"):
        name = name[:-4]
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


def ensure_clone(url, cache_dir):
    """Clone `url` under cache_dir, or update the existing clone's tags; return its path."""
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    repo_dir = cache_dir / clone_dir_name(url)
    if (repo_dir / ".git").is_dir():
        git(repo_dir, "fetch", "--quiet", "--tags", "--force")
    else:
        git(cache_dir, "clone", "--quiet", url, repo_dir.name)
    return repo_dir


def tag_for_version(repo_dir, package, version):
    """The repo tag for a release version, trying TAG_PATTERNS in order; None if no match."""
    tags = set(git(repo_dir, "tag", "--list").split())
    for pattern in TAG_PATTERNS:
        tag = pattern.format(package=package, version=version)
        if tag in tags:
            return tag
    return None
