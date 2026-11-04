"""Score the vulnerable-function records against the hand-checked truth set.

Reads both record folders (data/vulnfuncs and data/vulnfuncs/review) and the
signed-off truth files, and reports function recall and precision, entry-point
recall and status correctness. Names compare exactly.
"""

import argparse
import json
from pathlib import Path

from pipeline.record import folder_conflicts
from pipeline.repos import PipelineError

FUNCTION_RECALL_BAR = 0.90
FUNCTION_PRECISION_BAR = 0.90
ENTRYPOINT_RECALL_BAR = 0.95


def load_truth(truth_dir):
    """Signed-off truth files in truth_dir (top level only), keyed by ID."""
    truth = {}
    for path in sorted(Path(truth_dir).glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("signed_off") is not True:
            raise PipelineError(f"{path}: not signed off")
        truth[data["id"]] = data
    return truth


def load_records(records_dir):
    """Records from records_dir and records_dir/review, keyed by ID."""
    records_dir = Path(records_dir)
    conflicts = folder_conflicts(records_dir)
    if conflicts:
        raise PipelineError("records in both folders: " + ", ".join(conflicts))
    records = {}
    for folder in (records_dir, records_dir / "review"):
        for path in sorted(folder.glob("*.json")):
            if path.name == "index.json":
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            records[data["id"]] = data
    return records


def score(record, truth):
    """Score one record (or None) against its truth file."""
    truth_functions = [v["name"] for v in truth.get("vulnerable") or []]
    truth_entries = list(truth.get("entry_points") or [])
    result = {
        "function_hits": 0,
        "function_total": len(truth_functions),
        "false_functions": [],
        "record_functions": 0,
        "entrypoint_hits": 0,
        "entrypoint_total": len(truth_entries),
        "status_ok": False,
        "status_reason": "no record",
        "review": {"status": "missing", "kinds": []},
    }
    if record is None:
        return result

    names = [v["name"] for v in record.get("vulnerable") or []]
    entries = {e["name"] for e in record.get("entry_points") or []}
    result["function_hits"] = sum(1 for n in truth_functions if n in names)
    result["false_functions"] = [n for n in names if n not in truth_functions]
    result["record_functions"] = len(names)
    result["entrypoint_hits"] = sum(1 for n in truth_entries if n in entries)

    if record.get("status") == truth.get("status"):
        result["status_ok"], result["status_reason"] = True, "ok"
    else:
        result["status_reason"] = f"status {record.get('status')}, expected {truth.get('status')}"
    review = record.get("review") or {}
    result["review"] = {
        "status": review.get("status", "none"),
        "kinds": [r["kind"] for r in review.get("reasons") or []],
    }
    return result


def _ratio(hits, total):
    return hits / total if total else 1.0


def evaluate(records_dir, truth_dir):
    """Score every truth advisory; records_dir covers both folders."""
    truth = load_truth(truth_dir)
    records = load_records(records_dir)
    per_advisory = {i: score(records.get(i), t) for i, t in truth.items()}
    scores = list(per_advisory.values())

    recall = _ratio(sum(s["function_hits"] for s in scores),
                    sum(s["function_total"] for s in scores))
    record_total = sum(s["record_functions"] for s in scores)
    precision = _ratio(sum(s["function_hits"] for s in scores), record_total)
    entry_recall = _ratio(sum(s["entrypoint_hits"] for s in scores),
                          sum(s["entrypoint_total"] for s in scores))
    wrong = [f"{i}: {s['status_reason']}" for i, s in per_advisory.items() if not s["status_ok"]]
    statuses_correct = not wrong
    return {
        "function_recall": recall,
        "function_precision": precision,
        "entrypoint_recall": entry_recall,
        "statuses_correct": statuses_correct,
        "wrong_statuses": wrong,
        "in_review": [i for i, s in per_advisory.items() if s["review"]["status"] == "open"],
        "per_advisory": per_advisory,
        "meets_bar": (recall >= FUNCTION_RECALL_BAR and precision >= FUNCTION_PRECISION_BAR
                      and entry_recall >= ENTRYPOINT_RECALL_BAR and statuses_correct),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", default="data/vulnfuncs")
    parser.add_argument("--truth", default="data/handchecked")
    args = parser.parse_args(argv)

    result = evaluate(Path(args.records), Path(args.truth))
    width = max([len(i) for i in result["per_advisory"]] + [2])
    print(f"{'id':<{width}}  {'status':<6}  {'funcs':>7}  {'false':>5}  {'entry':>7}  review")
    for advisory_id, s in result["per_advisory"].items():
        review = s["review"]["status"]
        if s["review"]["kinds"]:
            review += " " + ",".join(s["review"]["kinds"])
        print(f"{advisory_id:<{width}}  {'ok' if s['status_ok'] else 'WRONG':<6}  "
              f"{s['function_hits']}/{s['function_total']:<5}  {len(s['false_functions']):>5}  "
              f"{s['entrypoint_hits']}/{s['entrypoint_total']:<5}  {review}")
    print(f"function recall:    {result['function_recall']:.3f}")
    print(f"function precision: {result['function_precision']:.3f}")
    print(f"entry-point recall: {result['entrypoint_recall']:.3f}")
    print(f"statuses correct:   {result['statuses_correct']}")
    print(f"in review: {len(result['in_review'])}")
    return 0 if result["meets_bar"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
