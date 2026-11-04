# Review Folder and Strict Entry-Point Walker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the strict entry-point walker, route every record it cannot connect to a public name into `data/vulnfuncs/review/`, and let a signed-off override move it back out.

**Architecture:** `pipeline/entrypoints.py` builds the package's call graph from the pre-fix tree and reports, per vulnerable item, either public entry points or a review reason with file and line. `pipeline/record.py` gains the `review` field, three override passes (commits, vulnerable items, entry points) and folder placement. `pipeline/run.py` composes the existing modules end to end and places each record; `pipeline/evaluate.py` scores both folders against the truth set.

**Tech Stack:** Python standard library (`ast`, `json`, `hashlib`, `argparse`, `unittest`) plus the `git` CLI through `pipeline.repos.git`.

**Spec:** `docs/superpowers/specs/2026-11-04-review-folder-design.md` (amends `2026-11-03-reachability-design.md`). This plan supersedes Tasks 8, 9 and 10 of `docs/superpowers/plans/2026-11-03-reachability-phase-a.md` and modifies the module Task 7 built.

## Global Constraints

- Pipeline code is stdlib Python; it may use the network and the `git` CLI only through `pipeline.repos.git`.
- Records live at `data/vulnfuncs/<ID>.json`; review records at `data/vulnfuncs/review/<ID>.json`. `index.json` covers the main folder only and never descends into `review/`.
- Every run writes exactly one copy of each advisory's record and deletes the copy in the other folder.
- The walker emits edges only for calls it resolves to a package definition (`high`) or method calls matched by name alone (`medium`). Never an edge from a value reference, a registration call, a decorator or a name pattern.
- Review reason kinds, verbatim: `referenced_not_called`, `no_reference`, `dead_end_chain`, `module_level`, `class_level`.
- Review resolve text, verbatim: `Do not edit: resolve in data/overrides.json and rerun`.
- Self-only note text, verbatim: `self-only entry point: <fqn> has no caller or reference inside the package`.
- `reviewed` in an override requires `note`; otherwise `PipelineError` naming the advisory. `signed_off` gates `reviewed` only.
- `PIPELINE_VERSION` becomes `"2"`.
- Accuracy bar (unchanged): function recall ≥ 0.90, function precision ≥ 0.90, entry-point recall ≥ 0.95, every status correct. The evaluator refuses a truth file with `signed_off: false`.
- Confidence (unchanged): `high` = passed release check, not a bundle; `medium` otherwise.
- `python -m unittest` from the repo root stays green after every task.
- Commit messages follow the repo's style: `Add pipeline.<module>: <what>` for new modules, `Change pipeline.<module>: <what>` for modified ones.

## Review Focus

Spec-implied failure modes no spec example exercises; each line's test is added to the owning task.

1. A package with two import folders where one copy does not parse (PyYAML `lib/` is Python 2): the walker keeps the copy that parses, notes the skipped one, never crashes (Task 2).
2. A vulnerable item that is not defined in the analysed tree (a deleted file, or a name verification gap): a `no_reference` reason with `file: null` and the detail `not defined in the analysed tree`, never a crash or a silent main-folder record (Task 3).
3. A call graph with a cycle and no root (`a` calls `b`, `b` calls `a`, nothing calls either): the closure walk terminates and the item is `dead_end_chain` with an empty `dead_ends` list (Task 3).
4. A record found in both folders before a run (interrupted run): the driver reprocesses it; `write_index` and the evaluator refuse with the ID (Tasks 1, 4, 5).
5. An override that sets `status: not_code` on a record with open reasons: `review.status` is `none`, `reasons` is empty, the record goes to the main folder (Task 1).

---

### Task 1: Review field, three override passes, placement — `pipeline/record.py`

**Files:**
- Modify: `pipeline/record.py` (`build_record`, `apply_overrides`, `write_index`, `PIPELINE_VERSION`)
- Test: `tests/test_record.py`

**Interfaces:**
- Consumes: `pipeline.repos.PipelineError`.
- Produces:
  - `PIPELINE_VERSION = "2"`; `REVIEW_RESOLVE = "Do not edit: resolve in data/overrides.json and rerun"`.
  - `build_record(merged, analysis) -> dict` — as today, plus analysis keys `review` (`{"tree": str | None, "reasons": list[dict]}`, both optional) and `overrides_applied` (list, optional, copied into the record). Output gains `review: {"status": "open" | "none", "tree": str | None, "reasons": list, "resolve": REVIEW_RESOLVE}` and `overrides_fingerprint: None`. `status` is `open` when `reasons` is non-empty and the record's `status` is `found`; otherwise `none` with `reasons: []`.
  - `override_commits(analysis: dict, spec: dict | None) -> dict` — new dict; applies `status` and `fix_commits` (replace with `{"sha", "source": "override", "in_fixed_release": None, "bundle": False}`); appends to `overrides_applied` (created when missing).
  - `override_vulnerable(analysis: dict, spec: dict | None) -> dict` — new dict; applies `remove_vulnerable` then `add_vulnerable` exactly as today's `apply_overrides` does; when the target carries `review.reasons`, drops the reasons whose `item` was removed.
  - `override_entry_points(record: dict, spec: dict | None) -> dict` — new dict; applies `remove_entry_points`, `add_entry_points`, `note`; then `reviewed`; then sets `overrides_fingerprint`. Rules: `reviewed` (list of item names, or `true`) with no `note` raises `PipelineError(f"{record['id']}: override marks items reviewed without a note")`. With `signed_off` absent or `false`: nothing changes and `overrides_applied` gains `"reviewed: not applied, unsigned"`. With `signed_off: true`: each listed name that matches an open reason's `item` gains `"reviewed <name>"`; a name with no open reason gains `"reviewed <name>: no open reason"`; when every open reason's item is covered (or `reviewed` is `true` and at least one reason exists), `review.status` becomes `"resolved"`. If the record's `status` is not `found`, `review` becomes `{"status": "none", "reasons": [], ...}` regardless.
  - `apply_overrides(record: dict, overrides: dict) -> dict` — the three passes in order on a finished record, keyed by `record["id"]`; keeps today's behaviour and tests.
  - `validate_overrides(overrides: dict) -> None` — raises `PipelineError` naming the advisory when `reviewed` is present without `note`, when `reviewed` is neither a list of strings nor `true`, or when `signed_off` is not a bool.
  - `overrides_fingerprint(spec: dict | None) -> str | None` — SHA-256 hex of `json.dumps(spec, sort_keys=True, separators=(",", ":"))`; `None` for a missing or empty spec.
  - `record_dir(record: dict, out_dir: Path) -> Path` — `out_dir / "review"` when `record["review"]["status"] == "open"`, else `out_dir`.
  - `place_record(record: dict, out_dir: Path) -> Path` — `write_record` into `record_dir`, delete `<other folder>/<id>.json` if it exists, return the written path.
  - `folder_conflicts(records_dir: Path) -> list[str]` — sorted IDs with a file in both `records_dir` and `records_dir / "review"`.
  - `write_index(records_dir)` — as today (non-recursive), but raises `PipelineError("records in both folders: " + ", ".join(ids))` when `folder_conflicts` is non-empty.

- [ ] **Step 1: Write the failing tests** in `tests/test_record.py`. Update `SPEC_KEYS` to add `review` and `overrides_fingerprint`. Add, with the exact values above:

```python
def test_review_open_when_reasons_and_found(self):
    built = record.build_record(merged_advisory(), analysis(review={"tree": "abc123", "reasons": [REASON]}))
    self.assertEqual(built["review"]["status"], "open")
    self.assertEqual(built["review"]["tree"], "abc123")
    self.assertEqual(built["review"]["resolve"], record.REVIEW_RESOLVE)
    self.assertIsNone(built["overrides_fingerprint"])

def test_review_none_when_no_reasons_or_not_found(self):  # status unknown + reasons -> none, reasons []

def test_override_commits_replaces_and_sets_status(self):

def test_override_vulnerable_drops_reasons_of_removed_items(self):

def test_reviewed_without_note_raises(self):  # PipelineError message contains the ID

def test_unsigned_reviewed_leaves_record_open(self):  # "reviewed: not applied, unsigned" in overrides_applied

def test_signed_reviewed_resolves_when_all_items_covered(self):  # status "resolved"; partial list -> still "open"

def test_reviewed_name_without_open_reason_is_recorded(self):  # "reviewed x: no open reason"; status stays "none"

def test_not_code_override_clears_open_reasons(self):  # Review Focus 5

def test_validate_overrides_rejects_bad_specs(self):

def test_fingerprint_is_stable_and_none_when_absent(self):

def test_place_record_routes_and_removes_stale_copy(self):  # open -> review/, stale main copy deleted; resolved -> main, stale review copy deleted

def test_write_index_refuses_both_folder_conflict(self):  # Review Focus 4; and index never lists review-only records
```

`REASON` is `{"item": "pkg.mod.f", "kind": "referenced_not_called", "file": "pkg/mod.py", "references": [{"file": "pkg/mod.py", "line": 9, "context": "value in dict literal TABLE"}], "dead_ends": []}` (the Task 3 reason shape).

- [ ] **Step 2: Run `python -m unittest tests.test_record -v`** — expected: the new tests FAIL or ERROR (missing names), the existing ones still pass.
- [ ] **Step 3: Implement the interfaces above in `pipeline/record.py`.** `apply_overrides` becomes a composition of the three passes; keep its docstring's list of keys and add `reviewed`, `signed_off`.
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add pipeline/record.py tests/test_record.py
git commit -m "Change pipeline.record: review field, three override passes, folder placement"
```

### Task 2: Call graph and entry points — `pipeline/entrypoints.py`

**Files:**
- Create: `pipeline/entrypoints.py`
- Test: `tests/test_entrypoints.py`

**Interfaces:**
- Consumes: `pipeline.commits.library_files_at`, `pipeline.repos.git`.
- Produces:
  - `sources_at(repo_dir: Path, rev: str, package: str) -> list[dict]` — `[{"module": str, "path": str, "source": str}]` for every library file of the package at `rev`, in `library_files_at` order. `package` is the PyPI name.
  - `sources_from_tree(root: Path, package: str) -> list[dict]` — same shape from a plain directory `root/<package>/**/*.py`; `module` from `commits.module_for_path`; `path` relative to `root` with `/` separators. For tests and for a checked-out tree.
  - `build_graph(sources: list[dict], package: str) -> Graph` — `package` is the import name (`yaml`, not `pyyaml`). `Graph` is a plain class with:
    - `defs: dict[str, dict]` — definition FQN → `{"kind": "function" | "method" | "class", "module": str, "file": str, "line": int}`; class FQN `pkg.mod.Cls`, method `pkg.mod.Cls.m`, nested defs excluded.
    - `callers: dict[str, list[tuple[str, str]]]` — callee FQN → `[(caller FQN, "high" | "medium")]`, no duplicates.
    - `public: dict[str, str]` — definition FQN → its shortest public import path, present only for public definitions (see rule below).
    - `references: dict[str, list[dict]]` — filled by Task 3; `{}` here.
    - `notes: list[str]` — skipped files.
    - `bases: dict[str, list[str]]` — class FQN → base class FQNs defined in the package, in order.
  - `walk(sources: list[dict], package: str, vulnerable: list[dict]) -> dict` — `vulnerable` items are `{"name": FQN, "kind": "function" | "method" | "class_level" | "module_level"}`. Returns `{"entry_points": list[dict], "reasons": list[dict], "notes": list[str]}`. In this task `reasons` is always `[]`; Task 3 fills it. Entry points are `{"name": public path, "defined_as": FQN, "confidence": "high" | "medium", "path": [FQN, ..., item FQN]}`, sorted by `name`, one per public definition in the item's backward closure (plus the item itself when public, with `path: [item]`). `confidence` is `high` when some chain from that definition to the item uses only `high` edges, else `medium`. `path` is a shortest chain by edge count.

Rules the implementer cannot infer:

- **Module dedupe and parse failures.** Two sources with the same `module` (PyYAML `lib/` and `lib3/`): keep the first that parses; note every skipped file as `"<path>: duplicate module <module>, skipped"` or `"<path>: does not parse (line N: msg), skipped"`. Review Focus 1.
- **Public rule.** A definition is public when no part of its dotted FQN starts with `_`, except a dunder part (`__init__`, `__call__`) which is public under its class: `public["pkg.mod.Cls.__init__"]` is the class's public path. Shortest public path: a name re-exported by `pkg/__init__.py` is `pkg.Name`; otherwise `pkg.mod.Name`; methods append `.m` to the class's path. Re-exports resolved in every `__init__.py`: `from .mod import Name [as Alias]`, `from pkg.mod import Name`, `from . import mod`, `import pkg.mod`, and `from .mod import *` (every public top-level definition of `mod`, or `__all__` when `mod` defines it as a list of string literals).
- **Name tables.** Per module: imports (`import pkg.x`, `import pkg.x as y`, `from .x import z`, `from pkg.x import z as w`, `from . import x`), module-level defs and classes. Relative imports resolve against the module's package. Anything else is unresolved.
- **High edges**, from the enclosing definition to the callee, for an `ast.Call` whose `func` is: a `Name` resolving to a package function or class; `self.m` / `cls.m` inside a method of class `C` → `C.m` or the first base in `bases[C]` (depth-first) that defines `m`; `super().m()` → the first base that defines `m`; `Cls.m` where `Cls` resolves to a package class; `mod.f` where `mod` resolves to a package module; `Cls(...)` → `Cls.__init__` when defined in `Cls` or a base, else the class FQN itself. Calls at module or class level (outside any def) attach to no caller and produce no edge.
- **Medium edges.** `<anything else>.m(...)` where `m` is the name of at least one package method: one edge from the enclosing definition to every package method named `m`.
- **No edge** for anything else, including decorators.

- [ ] **Step 1: Write the failing tests** in `tests/test_entrypoints.py`. Add a helper `make_pkg(root, files: dict[str, str])` that writes `root/pkg/<rel>` and returns `sources_from_tree(root, "pkg")`. Tests, each with its own small package:

```python
def test_public_caller_of_private_function_found(self):
    # pkg/core.py: def _inner(): ...  def run(): _inner()
    result = entrypoints.walk(src, "pkg", [{"name": "pkg.core._inner", "kind": "function"}])
    self.assertEqual([e["name"] for e in result["entry_points"]], ["pkg.core.run"])
    self.assertEqual(result["entry_points"][0]["path"], ["pkg.core.run", "pkg.core._inner"])
    self.assertEqual(result["entry_points"][0]["confidence"], "high")

def test_reexport_gives_shortest_public_path_with_defined_as(self):
    # pkg/__init__.py: from .core import run as run  ->  name "pkg.run", defined_as "pkg.core.run"

def test_star_reexport_lists_public_names(self):

def test_underscore_module_path_is_not_public(self):
    # pkg/_internal.py: def helper(): target()  -> helper is not an entry point

def test_vulnerable_public_function_is_its_own_entry_point(self):
    # path == [item]

def test_self_and_super_method_calls_resolve_through_bases(self):
    # Base.m calls self._v; Child(Base) has no _v; Child.run calls self.m -> entry points include pkg.Child.run and pkg.Base.m

def test_instantiation_is_an_edge_to_init(self):
    # def make(): return Cls()  ;  Cls.__init__ calls self._v  -> make and Cls (public path of __init__) are entry points

def test_unresolved_method_call_is_medium_edge(self):
    # def go(x): x.m()  with two classes defining m -> edges to both, confidence "medium"

def test_value_reference_is_not_an_edge(self):
    # TABLE = {"a": _v}  and nothing calls _v  -> entry_points == []  (reasons are Task 3)

def test_duplicate_module_keeps_parsing_copy(self):  # Review Focus 1: a lib/ copy with Python 2 print -> note, lib3/ copy used

def test_module_level_call_makes_no_edge(self):
```

- [ ] **Step 2: Run `python -m unittest tests.test_entrypoints -v`** — expected: ERROR, module missing.
- [ ] **Step 3: Implement `pipeline/entrypoints.py`** with the interfaces above. One `ast` pass per module builds `defs`, name tables and `bases`; a second pass over every definition body collects edges. Reverse adjacency (`callers`) is what `walk` needs.
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add pipeline/entrypoints.py tests/test_entrypoints.py
git commit -m "Add pipeline.entrypoints: call graph, public names, entry points"
```

### Task 3: References, roots and review reasons — `pipeline/entrypoints.py`

**Files:**
- Modify: `pipeline/entrypoints.py` (`build_graph` fills `references`; `walk` fills `reasons` and `notes`)
- Test: `tests/test_entrypoints.py`

**Interfaces:**
- Consumes: Task 2's `Graph`.
- Produces:
  - `Graph.references: dict[str, list[dict]]` — definition FQN → `[{"file": str, "line": int, "context": str}]`, one per `ast.Name` or `ast.Attribute` node that resolves (through the module's name table, or `Cls.m` / `mod.f` through the package) to a package definition and is **not** the `func` of an `ast.Call`. Decorators are not references (standard ones like `property` and `wraps` would otherwise mark every decorated function).
  - Context strings, verbatim: `value in dict literal <NAME>` when the `ast.Dict` is the value of an assignment to a single `Name` (else `value in dict literal`); `element of list literal` / `element of tuple literal` / `element of set literal`; `argument to <callee>` where `<callee>` is the last attribute part of the call's `func` (`FullConstructor.add_multi_constructor(...)` → `argument to add_multi_constructor`), keyword arguments included; `assigned to <target>` with `ast.unparse` of the target; `default argument of <def name>`; `returned from <def name>`; otherwise `referenced`.
  - `walk(...)["reasons"]` — one dict per unconnected item: `{"item": FQN, "kind": <kind>, "file": str | None, "references": list[dict], "dead_ends": list[dict]}`; `dead_ends` entries are `{"name": FQN, "references": list[dict]}`; `detail: str` is present only for the two special cases below.
  - `walk(...)["notes"]` — Task 2's notes plus the self-only note.

Rules:

- **Closure and roots.** From the item, the backward closure over `callers` (both confidences), cycle-safe. A root is a closure node with no callers. A root is clean when it is in `public` and `references[root]` is empty.
- **Connected** when at least one clean root other than the item exists. Connected items raise no reason.
- **Reasons for an unconnected item**, in this order of checks:
  1. kind `module_level` → `module_level`, `file` is the module's file (or `None` when not in sources).
  2. kind `class_level`: the class is in `public` → connected, entry point is the class (`path: [class]`), no reason; else `class_level`.
  3. item not in `defs` → `no_reference`, `file: None`, `detail: "not defined in the analysed tree"`. Review Focus 2.
  4. the item is its own only root: `references[item]` non-empty → `referenced_not_called` with those references; else (no caller, no reference) a public **function** (kind `function`, not `method`) → no reason, entry point `[item]`, note `self-only entry point: <fqn> has no caller or reference inside the package`; a method, or a private function → `no_reference`.
  5. the closure has no root at all (cycle) → `dead_end_chain`, `dead_ends: []`, `detail: "no root: every caller is itself called"`. Review Focus 3.
  6. otherwise → `dead_end_chain`, `dead_ends` = every root (each with its references), sorted by name.
- Entry points are unchanged by reasons: every public definition in the closure is still listed (dead chains included), as Task 2 does.

- [ ] **Step 1: Write the failing tests** in `tests/test_entrypoints.py`:

```python
def test_dict_value_registration_is_referenced_not_called(self):
    # pkg/filters.py: def do_attr(...): ...  FILTERS = {"attr": do_attr}
    reasons = entrypoints.walk(src, "pkg", [{"name": "pkg.filters.do_attr", "kind": "function"}])["reasons"]
    self.assertEqual(reasons[0]["kind"], "referenced_not_called")
    self.assertEqual(reasons[0]["references"], [{"file": "pkg/filters.py", "line": 3, "context": "value in dict literal FILTERS"}])
    # and do_attr is still its own entry point

def test_argument_registration_names_the_callee(self):
    # Cls.add_multi_constructor("tag", Cls.construct_new) at module level -> context "argument to add_multi_constructor"

def test_dead_end_chain_lists_registered_roots(self):
    # set_state called by Cls.apply (registered as above) -> kind dead_end_chain, dead_ends == [{"name": "pkg.c.Cls.apply", "references": [...]}]

def test_module_level_item_is_a_reason(self):

def test_class_level_public_class_is_connected_private_is_not(self):

def test_self_only_public_function_is_exempt_with_note(self):

def test_method_with_no_caller_or_reference_is_no_reference(self):

def test_item_missing_from_tree_is_no_reference_with_detail(self):  # Review Focus 2

def test_cycle_without_root_is_dead_end_with_empty_list(self):  # Review Focus 3

def test_connected_item_has_no_reason_even_with_a_dead_chain(self):  # one clean root + one registered root -> connected, both chains' public names listed

def test_medium_only_chain_is_connected(self):

def test_decorator_is_not_a_reference(self):  # @property on a public method with a real caller -> connected
```

- [ ] **Step 2: Run `python -m unittest tests.test_entrypoints -v`** — expected: the new tests FAIL (empty `reasons`, missing `references`).
- [ ] **Step 3: Implement the reference pass and the reason rules in `pipeline/entrypoints.py`.** The reference pass is one more visitor over each module that tracks the enclosing statement and call to produce the context string.
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add pipeline/entrypoints.py tests/test_entrypoints.py
git commit -m "Change pipeline.entrypoints: value references, roots, review reasons"
```

### Task 4: Evaluation harness over both folders — `pipeline/evaluate.py`

**Files:**
- Create: `pipeline/evaluate.py`
- Test: `tests/test_evaluate.py`

**Interfaces:**
- Consumes: record files (Task 1 shape), truth files (`data/handchecked/README.md` "File format"), `record.folder_conflicts`, `pipeline.repos.PipelineError`.
- Produces:
  - `load_truth(truth_dir: Path) -> dict[str, dict]` — top-level `*.json` only (never `deferred/`); raises `PipelineError(f"{path}: not signed off")` for any file with `signed_off` false.
  - `load_records(records_dir: Path) -> dict[str, dict]` — main folder and `review/`; raises `PipelineError("records in both folders: ...")` on conflicts (Review Focus 4).
  - `score(record: dict | None, truth: dict) -> dict` — `{"function_hits", "function_total", "false_functions": list[str], "record_functions", "entrypoint_hits", "entrypoint_total", "status_ok": bool, "status_reason": str, "review": {"status": str, "kinds": list[str]}}`. Names compare exactly. A missing record: zero hits, `status_ok` false, `status_reason` `"no record"`, `review` `{"status": "missing", "kinds": []}`.
  - `evaluate(records_dir: Path, truth_dir: Path) -> dict` — `function_recall`, `function_precision` (hits over all record functions across the set; `1.0` when the set has none), `entrypoint_recall`, `statuses_correct`, `wrong_statuses: list[str]` (`"<id>: <reason>"`), `in_review: list[str]`, `per_advisory: dict[id, score]`, `meets_bar: bool` (0.90 / 0.90 / 0.95 / statuses_correct).
  - `main(argv=None) -> int` — `--records data/vulnfuncs`, `--truth data/handchecked`; prints one row per advisory (id, status ok, functions `hits/total`, false count, entry points `hits/total`, review status and kinds), then the four numbers and `in review: N`; returns 0 when `meets_bar` else 1.

- [ ] **Step 1: Write the failing tests** in `tests/test_evaluate.py` on tmp dirs with 2–3 synthetic record/truth pairs: `test_recall_precision_counted_by_name`, `test_entrypoint_recall_counted_separately`, `test_missing_record_counts_as_all_missed_and_wrong_status`, `test_record_in_review_is_scored_and_listed` (its reason kinds appear in `per_advisory[id]["review"]["kinds"]` and the ID in `in_review`), `test_both_folders_conflict_refused`, `test_meets_bar_thresholds` (exactly 0.90 / 0.90 / 0.95 passes; one below fails), `test_unsigned_truth_file_refused`, `test_deferred_subfolder_ignored`.
- [ ] **Step 2: Run `python -m unittest tests.test_evaluate -v`** — expected: ERROR, module missing.
- [ ] **Step 3: Implement `pipeline/evaluate.py`.**
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add pipeline/evaluate.py tests/test_evaluate.py
git commit -m "Add pipeline.evaluate: accuracy against the truth set, both folders"
```

### Task 5: Pipeline driver with placement and freshness — `pipeline/run.py`

**Files:**
- Create: `pipeline/run.py`
- Test: `tests/test_run.py`

**Interfaces:**
- Consumes: `repos.find_repo_url`, `repos.ensure_clone`, `repos.tag_for_version`, `commits.collect_candidates`, `commits.resolve_candidates`, `commits.release_check`, `commits.is_version_bump`, `commits.is_release_bundle`, `commits.group_backports`, `commits.changed_library_files`, `commits.full_sha`, `commits.import_folders_at`, `functions.changed_functions`, `verify.verify_names`, `entrypoints.sources_at`, `entrypoints.walk`, every `record.*` from Task 1, `depscan.version_key`. `functions.changed_functions`, `verify.verify_names`, `entrypoints.sources_at` and `entrypoints.walk` are called through their module attributes so tests monkeypatch them.
- Produces:
  - `process_advisory(merged: dict, cache_dir: Path, out_dir: Path, overrides: dict) -> dict` — returns the placed record. Sequence:
    1. `spec = overrides.get(merged["id"])`. `repo = repos.find_repo_url(merged)`; `None` → unknown record, note `no GitHub repository found`.
    2. `repo_dir = repos.ensure_clone(repo, cache_dir)`.
    3. Candidates → `resolve_candidates(..., repo_url=repo)`. Unresolved ones go to `rejected_commits` as `{"sha", "url", "source", "reason": "unresolved"}`.
    4. `fixed_tag` from the smallest `fixed_versions` by `depscan.version_key`; `last_vulnerable_tag` from the largest `affected_versions`; both through `tag_for_version(repo_dir, merged["package"], version)`.
    5. Per resolved sha: `release_check` → when checked and (`not in_fixed` or `in_last_vulnerable`) reject with reason `release check: not in <fixed_tag>` or `release check: already in <last_vulnerable_tag>`; `is_version_bump` → reject `version bump only`; survivors become `fix_commits` entries `{"sha", "source", "in_fixed_release": in_fixed or None, "bundle": is_release_bundle(...)}`.
    6. `analysis = record.override_commits(analysis, spec)`. No fix commits and status not overridden → unknown, note `no usable fix commit`.
    7. `group_backports` over the fix commit SHAs; analyse the first sha of each group: `changed_library_files` → `functions.changed_functions(before, after, before_lines, after_lines, module)`; each vulnerable entry gains `file: path` and `commit: sha`; names deduplicated across commits (first wins). Notes: `fix adds <names>` and `cosmetic-only changes in <names>` when non-empty.
    8. `analysis = record.override_vulnerable(analysis, spec)`.
    9. Status: `found` when `vulnerable` is non-empty; `not_code` when `vulnerable`, `added` and `cosmetic` are all empty and the analysed commit touches at least one file outside the library `.py` set (`git diff --name-only sha^ sha` minus `library_files_at` paths); otherwise `unknown` with note `fix changes library code but no function or module-level statement`.
    10. `found` only: `names_verified_for = verify.verify_names(repo_dir, package, names, merged["affected_versions"])`; `tree = commits.full_sha(repo_dir, first_sha + "^")`; import name = last path part of `commits.import_folders_at(repo_dir, tree, package)[0]`; `result = entrypoints.walk(entrypoints.sources_at(repo_dir, tree, package), import_name, vulnerable)`; `analysis["entry_points"] = result["entry_points"]`, `analysis["review"] = {"tree": tree, "reasons": result["reasons"]}`, notes extended.
    11. `rec = record.override_entry_points(record.build_record(merged, analysis), spec)`; `record.place_record(rec, out_dir)`.
    - Any `PipelineError` raised in steps 2–10 → unknown record with note `pipeline error: <message>`, placed, never a crash.
  - `existing_record(out_dir: Path, advisory_id: str) -> dict | None` — the record from the main folder or `review/`; `None` when absent **or present in both** (a conflict is stale by definition, Review Focus 4).
  - `is_fresh(existing: dict | None, merged: dict, spec: dict | None) -> bool` — same `osv_modified`, `pipeline_version == record.PIPELINE_VERSION`, and `overrides_fingerprint == record.overrides_fingerprint(spec)`.
  - `main(argv=None) -> int` — `--advisory ID` (repeatable), `--all`, `--packages a,b`, `--export data/osv`, `--cache data/repo_cache`, `--out data/vulnfuncs`, `--overrides data/overrides.json`, `--force`. Loads and `validate_overrides`; skips fresh advisories unless `--force`; prints `<id>  <status>  <main|review>` per advisory and `in review: N` at the end; rebuilds the index with `record.write_index(out_dir)`; returns 0.

- [ ] **Step 1: Write the failing tests** in `tests/test_run.py`, with a setUp git repo in the style of `tests/test_commits.py` (one import folder `src/pkg`, a tagged vulnerable release, a fix commit, a tagged fixed release) and monkeypatched `functions.changed_functions`, `verify.verify_names`, `entrypoints.sources_at` and `entrypoints.walk` stand-ins: `test_end_to_end_found_record_in_main_folder` (stand-in walk returns one entry point, no reasons), `test_reasons_route_record_to_review_folder`, `test_move_between_folders_removes_stale_copy`, `test_both_folder_leftover_is_reprocessed`, `test_freshness_skips_unchanged_and_override_change_reprocesses`, `test_force_reprocesses`, `test_version_bump_only_candidate_gives_unknown`, `test_no_repo_gives_unknown_with_note`, `test_bundle_commit_caps_confidence_medium`, `test_not_code_when_only_non_library_files_change` (fix commit changes `data.pem` and a `__version__` line), `test_pipeline_error_becomes_unknown_record`, `test_index_rebuilt_and_excludes_review`.
- [ ] **Step 2: Run `python -m unittest tests.test_run -v`** — expected: ERROR, module missing.
- [ ] **Step 3: Implement `pipeline/run.py`.**
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit**

```bash
git add pipeline/run.py tests/test_run.py
git commit -m "Add pipeline.run: driver with review placement and freshness"
```

### Task 6: Fold the decisions into the design and the phase A plan

**Files:**
- Modify: `2026-11-03-reachability-design.md` (Part 1 step 9; "Overrides"; "Decisions")
- Modify: `docs/superpowers/plans/2026-11-03-reachability-phase-a.md` (Tasks 7–11, 13)
- Modify: `data/handchecked/README.md` ("Entry points" bullet, one sentence)

- [ ] **Step 1: Edit the design.** In step 9, replace the paragraph starting "The call graph inside a package has the same blind spots" with three sentences: edges only from resolved calls (`high`) and name-matched method calls (`medium`); nothing from value references or registrations; items the walker cannot connect send the record to `data/vulnfuncs/review/` with a reason, resolved through the overrides file (link the spec). In "Overrides", add that `reviewed` requires `note` and is gated by `signed_off`. Add Decision 5: "Strict walker and review folder (2026-11-04): see `docs/superpowers/specs/2026-11-04-review-folder-design.md`."
- [ ] **Step 2: Edit the phase A plan.** Under Task 7 add "Modified by `docs/superpowers/plans/2026-11-04-review-folder.md` Task 1". Replace the bodies of Tasks 8, 9 and 10 with one line each: "Superseded by `docs/superpowers/plans/2026-11-04-review-folder.md` Task 4 / Tasks 2–3 / Task 5." In Task 11, add to `load_db`: "the fallback scan reads `db_dir/*.json` only and never `review/`; a record in `review/` is absent". Insert before Task 13 a "Human gate 2" paragraph: the six review records must reach the main folder (signed overrides, see the review-folder plan Task 7) before Tasks 13 to 15 run.
- [ ] **Step 3: Edit the handchecked README.** In the "Jinja template filters" bullet, replace "they are expected to come from `data/overrides.json`" with "they come from `data/overrides.json`, drafted by the pipeline builder and signed off per entry by the owner".
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass (no code changed).
- [ ] **Step 5: Commit**

```bash
git add 2026-11-03-reachability-design.md docs/superpowers/plans/2026-11-03-reachability-phase-a.md data/handchecked/README.md
git commit -m "Record the strict walker and review folder decisions in the design and plan"
```

### Task 7: First run on the truth advisories and the override drafts (human gate)

**Files:**
- Modify: `data/overrides.json`
- Create: `data/vulnfuncs/*.json`, `data/vulnfuncs/review/*.json`, `data/vulnfuncs/index.json`

Needs the network. The ten IDs are the table in `data/handchecked/README.md`.

- [ ] **Step 1: Download the export**: `python -c "from pipeline import osv; osv.download_export('data/osv')"`. Expected: `data/osv/` holds the PyPI advisories.
- [ ] **Step 2: Run the ten advisories**: `python -m pipeline.run --advisory GHSA-6757-jp84-gxfx --advisory GHSA-8q59-q68h-6hv4 --advisory GHSA-x84v-xcm2-53pg --advisory GHSA-j8r2-6x86-q33q --advisory GHSA-9hjg-9r4m-mvj7 --advisory GHSA-q2x7-8rv6-6q7h --advisory GHSA-h75v-3vvj-5mfj --advisory GHSA-gmj6-6f8f-6699 --advisory GHSA-cpwx-vrp4-4pq7 --advisory GHSA-248v-346w-9cwc --export data/osv --cache data/repo_cache --out data/vulnfuncs`. Expected: `in review: 6`, with GHSA-6757-jp84-gxfx (`dead_end_chain`), GHSA-8q59-q68h-6hv4 (`module_level`), GHSA-h75v-3vvj-5mfj and GHSA-cpwx-vrp4-4pq7 (`referenced_not_called`), GHSA-gmj6-6f8f-6699 and GHSA-q2x7-8rv6-6q7h (`no_reference` or `dead_end_chain`) in `review/`; the other four in the main folder, GHSA-248v-346w-9cwc with status `not_code`. A record that lands elsewhere is a walker bug to fix in Task 2 or 3 with a new test, or a seventh case to add to the spec's table; either way, stop and report before continuing.
- [ ] **Step 3: Draft the six overrides** in `data/overrides.json`, one entry per review record: `reviewed` listing every reasoned item, `add_entry_points` taken from the truth file's `entry_points` (each with `defined_as` and a `path` ending at the item, written from the package source at the record's `tree`), a `note` that states the path in words and the tag checked, and `signed_off: false`.
- [ ] **Step 4: Rerun the six** with the same command. Expected: still `in review: 6`; each review record's `overrides_applied` contains `reviewed: not applied, unsigned` and its `entry_points` now include the drafted names.
- [ ] **Step 5: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 6: Commit**

```bash
git add data/overrides.json data/vulnfuncs
git commit -m "Draft overrides for the six review records (unsigned)"
```

- [ ] **Step 7: Stop.** Human gate 2: the owner checks each drafted note against the package source and flips `signed_off` to `true`, reruns the six, and confirms `in review: 0` before the phase A plan's Tasks 13 to 15 run. The evaluator (`python -m pipeline.evaluate`) runs only once the truth files are signed off too.
