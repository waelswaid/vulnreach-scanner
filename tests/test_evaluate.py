"""Unit tests for pipeline.evaluate: accuracy against the truth set, both folders.

Run from the repository root:
    python -m unittest tests.test_evaluate
"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from pipeline import evaluate
from pipeline.repos import PipelineError


def make_record(advisory_id, names=(), entry_points=(), status="found", reasons=()):
    return {
        "id": advisory_id,
        "status": status,
        "vulnerable": [{"name": n, "kind": "function"} for n in names],
        "entry_points": [{"name": n} for n in entry_points],
        "review": {"status": "open" if reasons else "none",
                   "reasons": [{"item": "x", "kind": k} for k in reasons]},
    }


def make_truth(advisory_id, names=(), entry_points=(), status="found", signed_off=True):
    return {
        "id": advisory_id,
        "status": status,
        "vulnerable": [{"name": n, "kind": "function"} for n in names],
        "entry_points": list(entry_points),
        "signed_off": signed_off,
    }


def dump(directory, data):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{data['id']}.json").write_text(json.dumps(data), encoding="utf-8")


class EvaluateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.records = Path(self._tmp.name) / "records"
        self.truth = Path(self._tmp.name) / "truth"
        self.records.mkdir()
        self.truth.mkdir()

    def test_recall_precision_counted_by_name(self):
        dump(self.truth, make_truth("A", ["p.a", "p.b", "p.c", "p.d"]))
        dump(self.records, make_record("A", ["p.a", "p.b", "p.c", "p.x"]))
        dump(self.truth, make_truth("B", ["q.a"]))
        dump(self.records, make_record("B", ["q.a", "q.b"]))
        result = evaluate.evaluate(self.records, self.truth)
        self.assertEqual(result["per_advisory"]["A"]["function_hits"], 3)
        self.assertEqual(result["per_advisory"]["A"]["false_functions"], ["p.x"])
        self.assertEqual(result["per_advisory"]["B"]["false_functions"], ["q.b"])
        self.assertAlmostEqual(result["function_recall"], 4 / 5)
        self.assertAlmostEqual(result["function_precision"], 4 / 6)

    def test_entrypoint_recall_counted_separately(self):
        dump(self.truth, make_truth("A", ["p.a"], ["api.f", "api.g"]))
        dump(self.records, make_record("A", ["p.a"], ["api.f", "api.h"]))
        result = evaluate.evaluate(self.records, self.truth)
        score = result["per_advisory"]["A"]
        self.assertEqual((score["entrypoint_hits"], score["entrypoint_total"]), (1, 2))
        self.assertAlmostEqual(result["entrypoint_recall"], 0.5)
        self.assertEqual(result["function_recall"], 1.0)

    def test_missing_record_counts_as_all_missed_and_wrong_status(self):
        dump(self.truth, make_truth("A", ["p.a", "p.b"], ["api.f"]))
        result = evaluate.evaluate(self.records, self.truth)
        score = result["per_advisory"]["A"]
        self.assertEqual((score["function_hits"], score["function_total"]), (0, 2))
        self.assertFalse(score["status_ok"])
        self.assertEqual(score["status_reason"], "no record")
        self.assertEqual(score["review"], {"status": "missing", "kinds": []})
        self.assertFalse(result["statuses_correct"])
        self.assertEqual(result["wrong_statuses"], ["A: no record"])
        self.assertEqual(result["function_recall"], 0.0)
        self.assertEqual(result["function_precision"], 1.0)

    def test_record_in_review_is_scored_and_listed(self):
        dump(self.truth, make_truth("A", ["p.a"]))
        dump(self.records / "review", make_record(
            "A", ["p.a"], reasons=["referenced_not_called", "dynamic_dispatch"]))
        result = evaluate.evaluate(self.records, self.truth)
        score = result["per_advisory"]["A"]
        self.assertEqual(score["function_hits"], 1)
        self.assertEqual(score["review"]["status"], "open")
        self.assertEqual(score["review"]["kinds"], ["referenced_not_called", "dynamic_dispatch"])
        self.assertEqual(result["in_review"], ["A"])

    def test_both_folders_conflict_refused(self):
        dump(self.records, make_record("A"))
        dump(self.records / "review", make_record("A"))
        with self.assertRaises(PipelineError) as ctx:
            evaluate.load_records(self.records)
        self.assertIn("records in both folders: A", str(ctx.exception))

    def test_meets_bar_thresholds(self):
        def run(function_hits, entry_hits, status="found"):
            with tempfile.TemporaryDirectory() as tmp:
                records, truth = Path(tmp) / "r", Path(tmp) / "t"
                names = [f"f{i}" for i in range(10)]
                eps = [f"e{i}" for i in range(20)]
                dump(truth, make_truth("A", names, eps))
                dump(records, make_record("A", names[:function_hits], eps[:entry_hits],
                                          status=status))
                return evaluate.evaluate(records, truth)["meets_bar"]
        self.assertTrue(run(9, 19))
        self.assertFalse(run(8, 19))
        self.assertFalse(run(9, 18))
        self.assertFalse(run(10, 20, status="unknown"))
        # precision: 9 of 10 true plus one false is 0.90; two false is below
        with tempfile.TemporaryDirectory() as tmp:
            records, truth = Path(tmp) / "r", Path(tmp) / "t"
            names = [f"f{i}" for i in range(9)]
            dump(truth, make_truth("A", names))
            dump(records, make_record("A", names + ["x"]))
            self.assertTrue(evaluate.evaluate(records, truth)["meets_bar"])
            dump(records, make_record("A", names + ["x", "y"]))
            self.assertFalse(evaluate.evaluate(records, truth)["meets_bar"])

    def test_unsigned_truth_file_refused(self):
        dump(self.truth, make_truth("A", signed_off=False))
        with self.assertRaises(PipelineError) as ctx:
            evaluate.load_truth(self.truth)
        self.assertIn("not signed off", str(ctx.exception))

    def test_deferred_subfolder_ignored(self):
        dump(self.truth, make_truth("A"))
        dump(self.truth / "deferred", make_truth("B", signed_off=False))
        self.assertEqual(list(evaluate.load_truth(self.truth)), ["A"])

    def test_main_returns_exit_code(self):
        dump(self.truth, make_truth("A", ["p.a"]))
        dump(self.records, make_record("A", ["p.a"]))
        argv = ["--records", str(self.records), "--truth", str(self.truth)]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(evaluate.main(argv), 0)
        self.assertIn("in review: 0", out.getvalue())
        (self.records / "A.json").unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(evaluate.main(argv), 1)


if __name__ == "__main__":
    unittest.main()
