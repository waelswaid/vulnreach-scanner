"""Build, correct and write the vulnerable-code records (design: "Record format").

One JSON file per advisory. Confidence follows the commit a function was
found in (high: passed the release check and not a bundle; medium
otherwise), and a function named in the advisory text is raised to high.
Hand overrides apply in three passes (fix commits before the diff, vulnerable
names before the entry-point walk, then entry points, the note and the review
sign-off on the built record) and are listed in the record, so regenerating
the database never loses a correction.
"""

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from pipeline.repos import PipelineError

PIPELINE_VERSION = "2"

# Written into every record's review field: review state is derived, never hand-edited.
REVIEW_RESOLVE = "Do not edit: resolve in data/overrides.json and rerun"

# A function or method mentioned in prose: `idna.encode()`, `extract_zipped_paths()`.
_MENTION_RE = re.compile(r"(?<![\w.])([A-Za-z_][\w.]*[\w])\(\)")


def commit_confidence(commit):
    """high when the commit passed the release check and is not a release bundle."""
    if commit.get("in_fixed_release") is True and not commit.get("bundle"):
        return "high"
    return "medium"


def text_cross_check(summary_text, names):
    """Match `name()` mentions in the advisory text against the changed functions."""
    mentions = []
    for match in _MENTION_RE.finditer(summary_text or ""):
        token = match.group(1)
        if token not in mentions:
            mentions.append(token)
    matched, unmatched = [], []
    for token in mentions:
        hits = [name for name in names if _mention_matches(token, name)]
        if hits:
            for name in hits:
                if name not in matched:
                    matched.append(name)
        else:
            unmatched.append(token)
    return {"matched": matched, "unmatched_mentions": unmatched}


def _mention_matches(token, name):
    """`idna.encode` matches `idna.core.encode`: same last part, same first part."""
    parts = token.split(".")
    if name == token:
        return True
    if not name.endswith("." + parts[-1]):
        return False
    return len(parts) == 1 or name.startswith(parts[0] + ".")


def build_record(merged, analysis):
    """Assemble the record from the merged advisory and the analysis results."""
    fix_commits = [dict(c) for c in analysis.get("fix_commits") or []]
    by_sha = {c.get("sha"): c for c in fix_commits}

    vulnerable = []
    for entry in analysis.get("vulnerable") or []:
        confidence = entry.get("confidence")
        if not confidence:
            commit = by_sha.get(entry.get("commit"))
            confidence = commit_confidence(commit) if commit else "medium"
        vulnerable.append({
            "name": entry["name"],
            "kind": entry.get("kind", "function"),
            "file": entry.get("file"),
            "confidence": confidence,
            "evidence": list(entry.get("evidence") or []),
        })

    check = text_cross_check(merged.get("summary_text", ""), [v["name"] for v in vulnerable])
    for entry in vulnerable:
        if entry["name"] in check["matched"]:
            entry["confidence"] = "high"
            entry["evidence"].append("named in the advisory text")
    notes = list(analysis.get("notes") or [])
    if check["unmatched_mentions"]:
        notes.append("advisory text mentions "
                     + ", ".join(f"{m}()" for m in check["unmatched_mentions"])
                     + ", which match no changed function")

    status = analysis.get("status", "unknown")
    given = analysis.get("review") or {}
    reasons = [copy.deepcopy(r) for r in given.get("reasons") or []]
    if not (reasons and status == "found"):
        reasons = []
    review = {
        "status": "open" if reasons else "none",
        "tree": given.get("tree"),
        "reasons": reasons,
        "resolve": REVIEW_RESOLVE,
    }

    return {
        "id": merged["id"],
        "aliases": list(merged.get("aliases") or []),
        "package": merged["package"],
        "ecosystem": merged.get("ecosystem", "PyPI"),
        "repo": analysis.get("repo"),
        "status": status,
        "fix_commits": fix_commits,
        "rejected_commits": [dict(c) for c in analysis.get("rejected_commits") or []],
        "vulnerable": vulnerable,
        "entry_points": [dict(e) for e in analysis.get("entry_points") or []],
        "names_verified_for": list(analysis.get("names_verified_for") or []),
        "notes": notes,
        "overrides_applied": list(analysis.get("overrides_applied") or []),
        "review": review,
        "overrides_fingerprint": None,
        "pipeline_version": PIPELINE_VERSION,
        "osv_modified": merged.get("modified"),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def overrides_fingerprint(spec):
    """SHA-256 of the canonical JSON of one advisory's override spec; None when absent."""
    if not spec:
        return None
    text = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_overrides(overrides):
    """Raise PipelineError, naming the advisory, for a malformed review override."""
    for advisory_id, spec in overrides.items():
        if not isinstance(spec, dict):
            continue
        if "reviewed" in spec:
            reviewed = spec["reviewed"]
            if not spec.get("note"):
                raise PipelineError(f"{advisory_id}: override marks items reviewed without a note")
            is_names = isinstance(reviewed, list) and all(isinstance(n, str) for n in reviewed)
            if not (is_names or reviewed is True):
                raise PipelineError(
                    f"{advisory_id}: reviewed must be a list of item names or true")
        if "signed_off" in spec and not isinstance(spec["signed_off"], bool):
            raise PipelineError(f"{advisory_id}: signed_off must be true or false")


def override_commits(analysis, spec):
    """Pass 1: apply status and fix_commits; returns a new dict."""
    result = copy.deepcopy(analysis)
    if not spec:
        return result
    applied = result.setdefault("overrides_applied", [])
    if "status" in spec:
        result["status"] = spec["status"]
        applied.append(f"status set to {spec['status']}")
    if "fix_commits" in spec:
        result["fix_commits"] = [
            {"sha": sha, "source": "override", "in_fixed_release": None, "bundle": False}
            for sha in spec["fix_commits"]
        ]
        applied.append("fix_commits replaced: " + ", ".join(s[:7] for s in spec["fix_commits"]))
    return result


def override_vulnerable(analysis, spec):
    """Pass 2: apply remove_vulnerable then add_vulnerable; returns a new dict.

    Review reasons about a removed item go with it.
    """
    result = copy.deepcopy(analysis)
    if not spec:
        return result
    applied = result.setdefault("overrides_applied", [])
    vulnerable = result.setdefault("vulnerable", [])

    for name in spec.get("remove_vulnerable") or []:
        vulnerable = [v for v in vulnerable if v["name"] != name]
        applied.append(f"removed vulnerable {name}")
        review = result.get("review")
        if review and review.get("reasons"):
            review["reasons"] = [r for r in review["reasons"] if r.get("item") != name]
            if not review["reasons"] and review.get("status") == "open":
                review["status"] = "none"
    for entry in spec.get("add_vulnerable") or []:
        vulnerable = [v for v in vulnerable if v["name"] != entry["name"]]
        vulnerable.append({
            "name": entry["name"],
            "kind": entry.get("kind", "function"),
            "file": entry.get("file"),
            "confidence": entry.get("confidence", "high"),
            "evidence": list(entry.get("evidence") or []) + ["hand override"],
        })
        applied.append(f"added vulnerable {entry['name']}")
    result["vulnerable"] = vulnerable
    return result


def override_entry_points(record, spec):
    """Pass 3: entry points, note, then the review sign-off; returns a new record."""
    result = copy.deepcopy(record)
    if not spec:
        return result
    applied = result["overrides_applied"]

    for name in spec.get("remove_entry_points") or []:
        result["entry_points"] = [e for e in result["entry_points"] if e["name"] != name]
        applied.append(f"removed entry point {name}")
    for entry in spec.get("add_entry_points") or []:
        result["entry_points"] = [e for e in result["entry_points"] if e["name"] != entry["name"]]
        result["entry_points"].append({
            "name": entry["name"],
            "defined_as": entry.get("defined_as", entry["name"]),
            "confidence": entry.get("confidence", "high"),
            "path": list(entry.get("path") or [entry["name"]]),
        })
        applied.append(f"added entry point {entry['name']}")

    if spec.get("note"):
        result["notes"].append(spec["note"])
        applied.append("note added")

    reviewed = spec.get("reviewed")
    if reviewed and not spec.get("note"):
        raise PipelineError(f"{record['id']}: override marks items reviewed without a note")
    review = result["review"]
    if reviewed:
        if spec.get("signed_off") is not True:
            applied.append("reviewed: not applied, unsigned")
        else:
            open_items = [r["item"] for r in review["reasons"]] if review["status"] == "open" else []
            names = open_items if reviewed is True else reviewed
            if reviewed is True and not open_items:
                applied.append("reviewed: no open reason")
            for name in names:
                if name in open_items:
                    applied.append(f"reviewed {name}")
                else:
                    applied.append(f"reviewed {name}: no open reason")
            if open_items and all(item in names for item in open_items):
                review["status"] = "resolved"
    if result["status"] != "found":
        review["status"] = "none"
        review["reasons"] = []

    result["overrides_fingerprint"] = overrides_fingerprint(spec)
    return result


def apply_overrides(record, overrides):
    """Apply the hand-written corrections for this record's ID; returns a new record.

    Override keys: status, fix_commits (replace, SHAs), add_vulnerable /
    remove_vulnerable (entries / names), add_entry_points /
    remove_entry_points (entries / names), note, reviewed (item names or
    true; needs a note), signed_off (bool; reviewed counts only when true).
    Three passes: commits, vulnerable names, entry points and review. Every
    operation is listed in overrides_applied.
    """
    spec = overrides.get(record["id"])
    result = override_commits(record, spec)
    result = override_vulnerable(result, spec)
    return override_entry_points(result, spec)


def write_record(record, out_dir):
    """Write <out_dir>/<id>.json with sorted keys and a trailing newline."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{record['id']}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def record_dir(record, out_dir):
    """<out_dir>/review for a record with open review reasons, else out_dir."""
    out_dir = Path(out_dir)
    return out_dir / "review" if record["review"]["status"] == "open" else out_dir


def place_record(record, out_dir):
    """Write the record into its folder and delete any copy in the other one."""
    out_dir = Path(out_dir)
    target = record_dir(record, out_dir)
    path = write_record(record, target)
    other = out_dir if target != out_dir else out_dir / "review"
    (other / path.name).unlink(missing_ok=True)
    return path


def folder_conflicts(records_dir):
    """Sorted IDs that have a file in both records_dir and records_dir/review."""
    records_dir = Path(records_dir)
    main = {p.stem for p in records_dir.glob("*.json") if p.name != "index.json"}
    review = {p.stem for p in (records_dir / "review").glob("*.json")}
    return sorted(main & review)


def write_index(records_dir):
    """Rebuild <records_dir>/index.json: every record ID and alias -> record ID."""
    records_dir = Path(records_dir)
    conflicts = folder_conflicts(records_dir)
    if conflicts:
        raise PipelineError("records in both folders: " + ", ".join(conflicts))
    index = {}
    for path in sorted(records_dir.glob("*.json")):
        if path.name == "index.json":
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        index[record["id"]] = record["id"]
        for alias in record.get("aliases") or []:
            index.setdefault(alias, record["id"])
    path = records_dir / "index.json"
    path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
