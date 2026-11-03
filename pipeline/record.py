"""Build, correct and write the vulnerable-code records (design: "Record format").

One JSON file per advisory. Confidence follows the commit a function was
found in (high: passed the release check and not a bundle; medium
otherwise), and a function named in the advisory text is raised to high.
Hand overrides are applied after the pipeline runs and are listed in the
record, so regenerating the database never loses a correction.
"""

import copy
import json
import re
from datetime import datetime, timezone
from pathlib import Path

PIPELINE_VERSION = "1"

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

    return {
        "id": merged["id"],
        "aliases": list(merged.get("aliases") or []),
        "package": merged["package"],
        "ecosystem": merged.get("ecosystem", "PyPI"),
        "repo": analysis.get("repo"),
        "status": analysis.get("status", "unknown"),
        "fix_commits": fix_commits,
        "rejected_commits": [dict(c) for c in analysis.get("rejected_commits") or []],
        "vulnerable": vulnerable,
        "entry_points": [dict(e) for e in analysis.get("entry_points") or []],
        "names_verified_for": list(analysis.get("names_verified_for") or []),
        "notes": notes,
        "overrides_applied": [],
        "pipeline_version": PIPELINE_VERSION,
        "osv_modified": merged.get("modified"),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def apply_overrides(record, overrides):
    """Apply the hand-written corrections for this record's ID; returns a new record.

    Override keys: status, fix_commits (replace, SHAs), add_vulnerable /
    remove_vulnerable (entries / names), add_entry_points /
    remove_entry_points (entries / names), note. Every operation is listed
    in overrides_applied.
    """
    result = copy.deepcopy(record)
    spec = overrides.get(record["id"])
    if not spec:
        return result
    applied = result["overrides_applied"]

    if "status" in spec:
        result["status"] = spec["status"]
        applied.append(f"status set to {spec['status']}")
    if "fix_commits" in spec:
        result["fix_commits"] = [
            {"sha": sha, "source": "override", "in_fixed_release": None, "bundle": False}
            for sha in spec["fix_commits"]
        ]
        applied.append("fix_commits replaced: " + ", ".join(s[:7] for s in spec["fix_commits"]))

    for name in spec.get("remove_vulnerable") or []:
        result["vulnerable"] = [v for v in result["vulnerable"] if v["name"] != name]
        applied.append(f"removed vulnerable {name}")
    for entry in spec.get("add_vulnerable") or []:
        result["vulnerable"] = [v for v in result["vulnerable"] if v["name"] != entry["name"]]
        result["vulnerable"].append({
            "name": entry["name"],
            "kind": entry.get("kind", "function"),
            "file": entry.get("file"),
            "confidence": entry.get("confidence", "high"),
            "evidence": list(entry.get("evidence") or []) + ["hand override"],
        })
        applied.append(f"added vulnerable {entry['name']}")

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
    return result


def write_record(record, out_dir):
    """Write <out_dir>/<id>.json with sorted keys and a trailing newline."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{record['id']}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_index(records_dir):
    """Rebuild <records_dir>/index.json: every record ID and alias -> record ID."""
    records_dir = Path(records_dir)
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
