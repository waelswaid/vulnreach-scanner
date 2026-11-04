"""Run the pipeline end to end: one advisory in, one placed record out.

For each advisory: find and clone the repository, pick the fix commits,
find the functions they change, verify the names across the affected
releases, walk the package for entry points, apply the hand overrides and
write the record into data/vulnfuncs/ or, with open review reasons, into
data/vulnfuncs/review/. A record whose advisory, pipeline version and
override are unchanged is fresh and skipped unless --force.

    python -m pipeline.run --advisory GHSA-8q59-q68h-6hv4
    python -m pipeline.run --packages pyyaml,requests
    python -m pipeline.run --all
"""

import argparse
import json
import sys
from pathlib import Path

import depscan
from pipeline import commits, entrypoints, functions, osv, record, repos, verify
from pipeline.repos import PipelineError


def process_advisory(merged, cache_dir, out_dir, overrides):
    """Analyse one merged advisory, place its record and return it."""
    spec = overrides.get(merged["id"])
    repo = repos.find_repo_url(merged)
    if repo is None:
        analysis = _unknown(None, "no GitHub repository found")
    else:
        try:
            analysis = _analyse(merged, repo, Path(cache_dir), spec)
        except PipelineError as exc:
            analysis = _unknown(repo, f"pipeline error: {exc}")
    rec = record.override_entry_points(record.build_record(merged, analysis), spec)
    record.place_record(rec, out_dir)
    return rec


def _unknown(repo, note):
    return {"repo": repo, "status": "unknown", "notes": [note]}


def _analyse(merged, repo, cache_dir, spec):
    """Steps 2-10 of the sequence; raises PipelineError when a step cannot complete."""
    package = merged["package"]
    repo_dir = repos.ensure_clone(repo, cache_dir)
    fix_commits, rejected = _select_fix_commits(merged, repo, repo_dir)
    analysis = {"repo": repo, "status": "unknown", "fix_commits": fix_commits,
                "rejected_commits": rejected, "notes": []}

    analysis = record.override_commits(analysis, spec)
    status_overridden = bool(spec) and "status" in spec
    if not analysis["fix_commits"] and not status_overridden:
        analysis["notes"].append("no usable fix commit")
        return analysis

    groups = commits.group_backports(repo_dir, [c["sha"] for c in analysis["fix_commits"]])
    analysed = [group[0] for group in groups]
    changes = _find_functions(repo_dir, analysed, package)
    analysis["vulnerable"] = changes["vulnerable"]
    analysis["notes"].extend(changes["notes"])

    analysis = record.override_vulnerable(analysis, spec)
    vulnerable = analysis["vulnerable"]
    if not status_overridden:
        analysis["status"] = _status(repo_dir, analysed, package, vulnerable, changes)
        if analysis["status"] == "unknown":
            analysis["notes"].append(
                "fix changes library code but no function or module-level statement")

    if analysis["status"] == "found" and vulnerable and not analysed:
        analysis["notes"].append("no fix commit to walk from; entry points need an override")
    elif analysis["status"] == "found" and vulnerable:
        names = [v["name"] for v in vulnerable]
        analysis["names_verified_for"] = verify.verify_names(
            repo_dir, package, names, merged["affected_versions"])
        tree = commits.full_sha(repo_dir, analysed[0] + "^")
        if tree is None:
            raise PipelineError(f"cannot resolve the parent of {analysed[0]}")
        folders = commits.import_folders_at(repo_dir, tree, package)
        if not folders:
            raise PipelineError(f"no import folder for {package} at {tree}")
        import_name = folders[0].rsplit("/", 1)[-1]
        result = entrypoints.walk(entrypoints.sources_at(repo_dir, tree, package),
                                  import_name, vulnerable)
        analysis["entry_points"] = result["entry_points"]
        analysis["review"] = {"tree": tree, "reasons": result["reasons"]}
        analysis["notes"].extend(result["notes"])
    return analysis


def _select_fix_commits(merged, repo, repo_dir):
    """(fix_commits, rejected_commits) after resolution, the release check and the bump filter."""
    candidates = commits.resolve_candidates(
        commits.collect_candidates(merged), repo_dir, repo_url=repo)
    package = merged["package"]
    fixed_tag = _tag(repo_dir, package, merged.get("fixed_versions"), min)
    last_vulnerable_tag = _tag(repo_dir, package, merged.get("affected_versions"), max)

    fix_commits, rejected, seen = [], [], set()
    for candidate in candidates:
        if not candidate.get("resolved"):
            rejected.append(_rejected(candidate, "unresolved"))
            continue
        sha = candidate["sha"]
        if sha in seen:
            continue
        seen.add(sha)
        check = commits.release_check(repo_dir, sha, fixed_tag, last_vulnerable_tag)
        if check["checked"] and not check["in_fixed"]:
            rejected.append(_rejected(candidate, f"release check: not in {fixed_tag}"))
        elif check["checked"] and check["in_last_vulnerable"]:
            rejected.append(
                _rejected(candidate, f"release check: already in {last_vulnerable_tag}"))
        elif commits.is_version_bump(repo_dir, sha):
            rejected.append(_rejected(candidate, "version bump only"))
        else:
            fix_commits.append({
                "sha": sha,
                "source": candidate["source"],
                "in_fixed_release": check["in_fixed"] or None,
                "bundle": commits.is_release_bundle(repo_dir, sha),
            })
    return fix_commits, rejected


def _rejected(candidate, reason):
    return {"sha": candidate.get("sha"), "url": candidate.get("url"),
            "source": candidate["source"], "reason": reason}


def _tag(repo_dir, package, versions, pick):
    """The tag of the smallest (min) or largest (max) version, or None."""
    if not versions:
        return None
    return repos.tag_for_version(repo_dir, package, pick(versions, key=depscan.version_key))


def _find_functions(repo_dir, shas, package):
    """Changed functions across the analysed commits; a name is kept from its first commit."""
    vulnerable, added, cosmetic, notes = [], [], [], []
    seen = set()
    for sha in shas:
        for changed in commits.changed_library_files(repo_dir, sha, package):
            result = functions.changed_functions(
                changed["before"], changed["after"],
                changed["before_lines"], changed["after_lines"], changed["module"])
            for entry in result["vulnerable"]:
                if entry["name"] in seen:
                    continue
                seen.add(entry["name"])
                vulnerable.append({**entry, "file": changed["path"], "commit": sha})
            added.extend(n for n in result["added"] if n not in added)
            cosmetic.extend(n for n in result["cosmetic"] if n not in cosmetic)
            notes.extend(result["notes"])
    if added:
        notes.append("fix adds " + ", ".join(added))
    if cosmetic:
        notes.append("cosmetic-only changes in " + ", ".join(cosmetic))
    return {"vulnerable": vulnerable, "added": added, "cosmetic": cosmetic, "notes": notes}


def _status(repo_dir, shas, package, vulnerable, changes):
    """found, not_code or unknown (design: the status rule)."""
    if vulnerable:
        return "found"
    if not changes["added"] and not changes["cosmetic"] and any(
            _touches_non_library_file(repo_dir, sha, package) for sha in shas):
        return "not_code"
    return "unknown"


def _touches_non_library_file(repo_dir, sha, package):
    """True when the commit changes a file outside the package's library .py set."""
    changed = set(repos.git(repo_dir, "diff", "--name-only", f"{sha}^", sha).split("\n")) - {""}
    library = {path for rev in (f"{sha}^", sha)
               for path, _ in commits.library_files_at(repo_dir, rev, package)}
    return bool(changed - library)


def existing_record(out_dir, advisory_id):
    """The record in out_dir or out_dir/review; None when absent or in both folders."""
    out_dir = Path(out_dir)
    paths = [p for p in (out_dir / f"{advisory_id}.json", out_dir / "review" / f"{advisory_id}.json")
             if p.is_file()]
    if len(paths) != 1:
        return None
    return json.loads(paths[0].read_text(encoding="utf-8"))


def is_fresh(existing, merged, spec):
    """True when the record was built from this advisory, pipeline version and override."""
    if existing is None:
        return False
    return (existing.get("osv_modified") == merged.get("modified")
            and existing.get("pipeline_version") == record.PIPELINE_VERSION
            and existing.get("overrides_fingerprint") == record.overrides_fingerprint(spec))


def load_overrides(path):
    """The overrides file as a dict; {} when it does not exist."""
    path = Path(path)
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--advisory", action="append", default=[], metavar="ID",
                        help="advisory ID to process (repeatable)")
    parser.add_argument("--all", action="store_true", help="process every advisory")
    parser.add_argument("--packages", help="comma-separated PyPI package names")
    parser.add_argument("--export", default="data/osv")
    parser.add_argument("--cache", default="data/repo_cache")
    parser.add_argument("--out", default="data/vulnfuncs")
    parser.add_argument("--overrides", default="data/overrides.json")
    parser.add_argument("--force", action="store_true", help="reprocess fresh records too")
    args = parser.parse_args(argv)
    if not (args.advisory or args.all or args.packages):
        parser.error("give --advisory, --packages or --all")

    overrides = load_overrides(args.overrides)
    record.validate_overrides(overrides)
    packages = [p.strip() for p in args.packages.split(",") if p.strip()] if args.packages else None
    advisories = osv.load_merged(Path(args.export), packages=packages)
    if args.advisory:
        wanted = set(args.advisory)
        advisories = {key: merged for key, merged in advisories.items()
                      if key in wanted or merged["id"] in wanted}

    out_dir = Path(args.out)
    in_review = 0
    for key in sorted(advisories):
        merged = advisories[key]
        spec = overrides.get(merged["id"])
        rec = existing_record(out_dir, merged["id"])
        if args.force or not is_fresh(rec, merged, spec):
            rec = process_advisory(merged, Path(args.cache), out_dir, overrides)
        folder = "review" if record.record_dir(rec, out_dir) != out_dir else "main"
        in_review += folder == "review"
        print(f"{merged['id']}  {rec['status']}  {folder}")
    print(f"in review: {in_review}")
    record.write_index(out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
