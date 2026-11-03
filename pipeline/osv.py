"""Load OSV's PyPI advisory export and merge advisories that describe the same issue.

OSV publishes one JSON file per advisory. The same vulnerability usually
appears several times under different IDs (a GHSA entry, a PYSEC entry, ...)
that list each other as aliases. The pipeline works on one merged advisory
per issue, keyed by the GHSA ID when there is one, which is also the
`vulnerability_id` depscan writes in its findings.

Developer tool: may use the network (download_export). Standard library only.
"""

import json
import urllib.request
import zipfile
from pathlib import Path

import depscan

PYPI_EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"


def download_export(dest_dir, url=PYPI_EXPORT_URL):
    """Download OSV's PyPI export zip into dest_dir and extract it there."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    archive = dest_dir / "all.zip"
    with urllib.request.urlopen(url) as response, archive.open("wb") as out:
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest_dir)


def load_merged(export_dir, packages=None):
    """Read every advisory in export_dir and merge aliased ones.

    Returns {key: merged advisory}. The key is the merged advisory's `id`,
    or `<id>:<package>` when one advisory affects several PyPI packages
    (then each package gets its own entry with its own version data).
    With `packages`, only entries for those (normalized) names are returned.
    """
    wanted = None
    if packages is not None:
        wanted = {depscan.normalize_name(name, "PyPI") for name in packages}

    advisories = []
    for path in sorted(Path(export_dir).glob("*.json")):
        advisories.append(json.loads(path.read_text(encoding="utf-8")))

    merged = {}
    for group in _group_by_alias(advisories):
        for key, entry in _merge_group(group):
            if wanted is None or entry["package"] in wanted:
                merged[key] = entry
    return merged


def _group_by_alias(advisories):
    """Union-find over advisory IDs and aliases; returns lists of advisories."""
    parent = {}

    def find(node):
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    for advisory in advisories:
        for alias in advisory.get("aliases") or []:
            root_a, root_b = find(advisory["id"]), find(alias)
            if root_a != root_b:
                parent[root_a] = root_b

    groups = {}
    for advisory in advisories:
        groups.setdefault(find(advisory["id"]), []).append(advisory)
    return [sorted(group, key=lambda a: a["id"]) for group in groups.values()]


def _merge_group(advisories):
    """Merge one alias group into (key, entry) pairs, one per affected package."""
    ids = [a["id"] for a in advisories]
    primary = depscan.pick_primary_id(ids)
    names = set(ids)
    for advisory in advisories:
        names.update(advisory.get("aliases") or [])

    links = []
    seen_links = set()
    for advisory in advisories:
        for ref in advisory.get("references") or []:
            url = ref.get("url")
            if url and url not in seen_links:
                seen_links.add(url)
                links.append({"type": ref.get("type", ""), "url": url})

    texts = []
    for advisory in advisories:
        for field in ("summary", "details"):
            text = (advisory.get(field) or "").strip()
            if text and text not in texts:
                texts.append(text)

    by_package = {}
    for advisory in advisories:
        for affected in advisory.get("affected") or []:
            package = affected.get("package") or {}
            if package.get("ecosystem") != "PyPI":
                continue
            name = depscan.normalize_name(package.get("name", ""), "PyPI")
            bucket = by_package.setdefault(
                name, {"git_ranges": [], "versions": set(), "fixed": []}
            )
            bucket["versions"].update(affected.get("versions") or [])
            for rng in affected.get("ranges") or []:
                if rng.get("type") == "GIT":
                    for pair in _git_pairs(rng):
                        if pair not in bucket["git_ranges"]:
                            bucket["git_ranges"].append(pair)
                else:
                    for event in rng.get("events") or []:
                        fixed = event.get("fixed")
                        if fixed and fixed not in bucket["fixed"]:
                            bucket["fixed"].append(fixed)

    shared = {
        "id": primary,
        "aliases": sorted(names - {primary}),
        "ecosystem": "PyPI",
        "modified": max(a.get("modified") or "" for a in advisories),
        "links": links,
        "summary_text": "\n\n".join(texts),
        "raw": advisories,
    }
    multi = len(by_package) > 1
    entries = []
    for name in sorted(by_package):
        bucket = by_package[name]
        entry = dict(shared)
        entry["package"] = name
        entry["git_ranges"] = bucket["git_ranges"]
        entry["affected_versions"] = sorted(bucket["versions"], key=depscan.version_key)
        entry["fixed_versions"] = sorted(bucket["fixed"], key=depscan.version_key)
        key = f"{primary}:{name}" if multi else primary
        entries.append((key, entry))
    return entries


def _git_pairs(rng):
    """(introduced, fixed) commit pairs from one GIT range, in event order."""
    pairs = []
    introduced = None
    for event in rng.get("events") or []:
        if "introduced" in event:
            introduced = event["introduced"]
        if event.get("fixed"):
            pairs.append({"repo": rng.get("repo", ""), "introduced": introduced,
                          "fixed": event["fixed"]})
    return pairs
