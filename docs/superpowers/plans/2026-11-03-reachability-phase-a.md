# Reachability Phase A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the vulnerable-code database pipeline (problem 1, phase A) and the scan-side reachability check (problem 2), so depscan can mark each finding reachable, not_found or unknown behind `--experimental-reachability`.

**Architecture:** An offline pipeline (`pipeline/` package, developer tool: may use network and the `git` CLI) turns OSV PyPI advisories into one JSON record per advisory in `data/vulnfuncs/`, scored continuously against a hand-checked truth set. The scan side (`reachability.py`, stdlib-only like v0.1) looks records up by ID or alias and checks the project's imports and calls against the record's vulnerable functions and entry points. `depscan.py` gains the flag, statuses and report changes.

**Tech Stack:** Python 3.14 stdlib only (`ast`, `json`, `urllib.request`, `zipfile`, `subprocess`, `unittest`); the `git` CLI for the pipeline. No third-party packages.

**Spec:** `2026-11-03-reachability-design.md` (the executor reads it alongside this plan). Phase B (advisories without fix links) is out of scope per the spec.

## Human gate

Agents implement every task, test-first (spec Decision 3). The one human step is Task 1's sign-off: the owner signs the truth set before any pipeline code is judged against it, so the accuracy numbers aren't the pipeline graded against its own unreviewed answers.

## Global Constraints

- Scan side (`reachability.py`, `depscan.py`): offline, Python standard library only.
- Pipeline (`pipeline/`): may use network and the `git` CLI; still stdlib Python.
- Storage is JSON files, no database server. Records live at `data/vulnfuncs/<ID>.json`, keyed by GHSA ID when one exists.
- A finding depscan can't analyse reliably is **unknown** — never dropped, never guessed down to not_found.
- Fields are added to findings only in the version that fills them: `reachability`, `reachability_reason`, `call_sites` appear only when the flag runs.
- `names_verified_for` specifiers are restricted to the form `">=X, <Y"` with numeric-only release versions; the pipeline writes only this form and `reachability.py` only parses it (this bounds PEP 440 to what `depscan.version_key` handles).
- Accuracy bar (spec Decision 4): function recall ≥ 90%, function precision ≥ 90%, entry-point recall ≥ 95%, every `not_code`/`unknown` status correct.
- Reachability runs only with `--experimental-reachability` until the bar is met; without it, depscan behaves exactly like v0.1.
- not_found report copy, verbatim: `no call from your code; calls from other packages were not checked`.
- Confidence: `high` = passed release check, not a bundle, not cosmetic; `medium` = release check skipped (no tag matched) or bundle. (`low` is phase B.)
- Tests: `python -m unittest` from the repo root must stay green after every task.
- The pipeline maintains `data/vulnfuncs/index.json` (every record ID and alias → record ID); the scan side opens only the index plus the records its findings need, never the whole directory.

## Review Focus

Spec-implied failure modes no spec example exercises; each line's test is added to the owning task below.

1. Installed version outside `names_verified_for` → unknown, not not_found (Task 12).
2. A project file that fails to parse → unknown, never not_found — silence from a file we couldn't read is not evidence (Task 12).
3. A vulnerable call inside `.venv/` or `site-packages/` must neither mark the finding reachable nor count as project code (Task 12).
4. `from yaml import *` in the project → unknown, because calls can no longer be resolved (Tasks 11, 12).
5. A record whose `entry_points` list is empty or all-medium → never not_found (Task 12).

---

### Task 1: Hand-checked truth set

**Files:**
- Create: `data/handchecked/<ID>.json` (one per advisory, 28 files)
- Create: `data/handchecked/README.md`

**Interfaces:**
- Produces: truth files in the same shape as pipeline records (spec "Record format") restricted to the judged fields: `id`, `aliases`, `package`, `status`, `fix_commits` (shas only), `vulnerable` (names + kind), `entry_points` (names only), plus `truth_evidence`: a list of sentences with commit/advisory links justifying each entry.

- [ ] **Step 1: Enumerate the 28 advisories.** Fetch the OSV advisories for `pyyaml`, `requests`, `jinja2`, `urllib3`, `idna`, `certifi` from `https://osv-vulnerabilities.storage.googleapis.com/PyPI/<name>/all.zip` (or per-ID `https://api.osv.dev/v1/vulns/<id>`), save the raw JSON to the session scratchpad (not the repo), and list the merged advisory IDs. Expected: 28 merged advisories.
- [ ] **Step 2: Draft each truth file** by cloning each repo to the scratchpad and reading the fix commits and advisory text. The spec's known tricky cases must come out as: idna release-bump → the real fix commit found or `status: unknown`; the unrelated urllib3 refactor → absent from `fix_commits`; urllib3 1.24.2 bundle → present, functions judged individually; PyYAML → both fix commits, functions named once despite `lib/` + `lib3/`; certifi → `status: not_code`, empty `vulnerable`.
- [ ] **Step 3: Write `data/handchecked/README.md`**: what the set is, the sign-off rule (no pipeline code is judged against an unsigned set), and a `signed_off: false` line per file until the owner flips it.
- [ ] **Step 4: Commit** (`git add data/handchecked && git commit -m "Add hand-checked truth set for 28 research advisories (unsigned)"`).
- [ ] **Step 5: Hand off.** Report to the owner which entries you are least sure of. **Gate:** the owner flips `signed_off: true` per file; Task 8's evaluator refuses unsigned files.

### Task 2: OSV advisory loading and merging — `pipeline/osv.py`

**Files:**
- Create: `pipeline/__init__.py` (empty), `pipeline/osv.py`
- Modify: `.gitignore` (add `data/osv/`, `data/repo_cache/`)
- Test: `tests/test_osv.py`

**Interfaces:**
- Consumes: `depscan.pick_primary_id`, `depscan.normalize_name`.
- Produces:
  - `download_export(dest_dir: Path, url: str = PYPI_EXPORT_URL) -> None` — downloads and extracts OSV's PyPI `all.zip`.
  - `load_merged(export_dir: Path, packages: set[str] | None = None) -> dict[str, dict]` — merges advisories that alias each other; key and `id` = `pick_primary_id` over the group's IDs (GHSA preferred). Merged dict keys: `id`, `aliases` (sorted, excluding `id`), `package` (normalized), `ecosystem`, `modified` (max ISO string), `links` (deduped `{"type","url"}`), `git_ranges` (`{"repo","introduced","fixed"}`), `affected_versions` (sorted list), `fixed_versions` (list), `summary_text` (summary + details joined), `raw` (list of source advisories).

- [ ] **Step 1: Write failing tests** in `tests/test_osv.py` against small advisory dicts written inline (no network): `test_aliased_advisories_merge_into_one` (a GHSA and a PYSEC aliasing each other → one entry keyed by the GHSA ID, PYSEC in `aliases`), `test_package_filter_uses_normalized_names` (`packages={"typing-extensions"}` matches an advisory for `typing_extensions`), `test_git_ranges_and_links_collected`, `test_modified_is_max_across_sources`, `test_multi_package_advisory_gets_one_entry_per_package` (key becomes `<id>:<package>` when an advisory affects more than one PyPI package). Load via a helper that writes the dicts to `tmp/export/*.json` so `load_merged` reads files, like production.
- [ ] **Step 2: Run `python -m unittest tests.test_osv -v`** — expected: ERROR, no module `pipeline.osv`.
- [ ] **Step 3: Implement `pipeline/osv.py`.** `download_export` is a thin `urllib.request` + `zipfile` function, untested beyond by-hand use.
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit.**

### Task 3: Repo discovery, clone cache, tag matching — `pipeline/repos.py`

**Files:**
- Create: `pipeline/repos.py`
- Test: `tests/test_repos.py`

**Interfaces:**
- Consumes: merged advisory dicts (Task 2).
- Produces:
  - `class PipelineError(Exception)`
  - `git(repo_dir: Path, *args: str) -> str` — runs `git -C repo_dir`, returns stdout, raises `PipelineError` with stderr on nonzero exit.
  - `find_repo_url(merged: dict) -> str | None` — precedence: `git_ranges[].repo`, then a `PACKAGE`/`REPO`-typed GitHub link, then PyPI project URLs via `https://pypi.org/pypi/<name>/json` (network; the fetch lives in `fetch_pypi_urls(package: str) -> list[str]` so tests inject instead).
  - `ensure_clone(url: str, cache_dir: Path) -> Path` — clone or `git fetch --tags` an existing cache dir named after the repo.
  - `tag_for_version(repo_dir: Path, package: str, version: str) -> str | None` — tries `v{v}`, `{v}`, `{package}-{v}` against `git tag`, returns the first existing or None.

- [ ] **Step 1: Write failing tests.** For git behavior build a throwaway repo in `setUp` with `subprocess` (`git init`, two commits, tags `v1.0` and `pkg-2.0`): `test_tag_for_version_tries_patterns_in_order`, `test_tag_for_version_none_when_no_pattern_matches`, `test_git_raises_pipeline_error_with_stderr`. For URL precedence use dicts: `test_repo_url_prefers_git_ranges_over_links`, `test_repo_url_falls_back_to_injected_pypi_urls`.
- [ ] **Step 2: Run tests** — expected: ERROR, module missing.
- [ ] **Step 3: Implement `pipeline/repos.py`.**
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit.**

### Task 4: Candidate commits, release check, filters — `pipeline/commits.py`

**Files:**
- Create: `pipeline/commits.py`
- Test: `tests/test_commits.py`

**Interfaces:**
- Consumes: `repos.git`, `repos.tag_for_version`, merged advisory dicts.
- Produces:
  - `collect_candidates(merged: dict) -> list[dict]` — candidate: `{"sha": str|None, "url": str|None, "source": "git_range"|"commit_link"|"pr_link"|"compare_link", "resolved": bool}`. GitHub commit/PR/compare URLs parsed by pattern; non-GitHub hosts kept with `resolved: False` (spec: recorded, not resolved).
  - `resolve_candidates(candidates: list[dict], repo_dir: Path) -> list[dict]` — PR links to merge commits via `git log --grep` on `Merge pull request #N` / `(#N)`; compare links `a...b` to `git rev-list a..b`.
  - `release_check(repo_dir, sha, fixed_tag: str|None, last_vulnerable_tag: str|None) -> dict` — `{"in_fixed": bool|None, "in_last_vulnerable": bool|None, "checked": bool}` via `git merge-base --is-ancestor`; `checked: False` when either tag is None.
  - `is_version_bump(repo_dir, sha: str) -> bool` — True when the diff touches only version strings, changelogs and docs.
  - `is_release_bundle(repo_dir, sha: str) -> bool` — True when a release tag points at the commit (`git tag --points-at`).
  - `group_backports(repo_dir, shas: list[str]) -> list[list[str]]` — groups by `git patch-id --stable`.
  - `changed_library_files(repo_dir, sha: str, package: str) -> list[dict]` — per kept file: `{"path", "module", "before": str, "after": str, "before_lines": list[int], "after_lines": list[int]}`. Keeps `.py` files under the package's import folder (a directory containing `__init__.py` whose name normalizes to the package name, searched at repo root, under `src/`, `lib/`, `lib3/`); drops everything else (tests, docs, `dummyserver/`-style helpers). `module` is the dotted path from the import folder's parent (`lib3/yaml/constructor.py` → `yaml.constructor`). Changed line numbers parsed from `git diff` hunk headers; before/after text via `git show sha^:path` / `sha:path` (deleted file → `after` is `""`).

- [ ] **Step 1: Write failing tests** using a `setUp` repo with tags, a bump-only commit, a code commit under `src/pkg/`, a tagged release commit, and the same patch cherry-picked onto a branch: `test_collects_candidates_from_ranges_and_links`, `test_non_github_link_recorded_unresolved`, `test_release_check_ancestor_logic`, `test_release_check_unchecked_without_tags`, `test_version_bump_detected`, `test_release_bundle_detected_by_tag`, `test_backports_grouped_by_patch_id`, `test_changed_library_files_filters_and_maps_modules` (asserts the test-file change is dropped and `module == "pkg.mod"`), `test_changed_lines_match_diff`.
- [ ] **Step 2: Run tests** — expected: ERROR, module missing.
- [ ] **Step 3: Implement `pipeline/commits.py`.**
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit.**

### Task 5: Changed-function finder — `pipeline/functions.py`

**Files:**
- Create: `pipeline/functions.py`
- Test: `tests/test_functions.py`

**Interfaces:**
- Consumes: the per-file dicts from `commits.changed_library_files`.
- Produces: `changed_functions(before: str, after: str, before_lines: list[int], after_lines: list[int], module: str) -> dict` returning `{"vulnerable": [{"name": str, "kind": "function"|"method"|"class_level"|"module_level", "change": "modified"|"deleted", "evidence": list[str]}], "added": list[str]}`. Names are fully qualified (`yaml.constructor.FullConstructor.construct_python_object_new`). Spec rules: innermost containing function via `ast`; added functions excluded but listed in `added`; deleted included; docstring/comment/formatting-only changes excluded (compare `ast.dump` of before vs after bodies with docstrings stripped); changes outside any function → `class_level` with the class FQN or `module_level` with the module name.

- [ ] **Step 1: Write failing tests**: `test_modified_method_named_fully_qualified`, `test_added_function_excluded_but_recorded`, `test_deleted_function_included`, `test_docstring_only_change_excluded`, `test_formatting_only_change_excluded`, `test_class_level_default_change_reported` (a class attribute default changes → kind `class_level`, name is the class FQN), `test_module_level_constant_change_reported`, `test_nested_function_maps_to_innermost`. Each test is a pair of small inline sources plus the changed line numbers.
- [ ] **Step 2: Run `python -m unittest tests.test_functions -v`** — expected: ERROR, module missing.
- [ ] **Step 3: Implement `pipeline/functions.py`.**
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit.**

### Task 6: Name verification across affected versions — `pipeline/verify.py`

**Files:**
- Create: `pipeline/verify.py`
- Test: `tests/test_verify.py`

**Interfaces:**
- Consumes: `repos.git`, `repos.tag_for_version`.
- Produces:
  - `collect_names(source: str, module: str) -> set[str]` — FQNs of every function, method and class defined in the source (own small `ast` walk, independent of Task 5's changed-function finder).
  - `verify_names(repo_dir: Path, package: str, names: list[str], affected_versions: list[str]) -> list[str]` — for the newest tag of each affected `major.minor` series, check every name in `names` exists in that tag's package source; return maximal contiguous verified ranges as restricted specifiers, e.g. `[">=5.1, <5.4"]` (Global Constraints form). Series with no matching tag are not verified (excluded from the ranges).

- [ ] **Step 1: Write failing tests**: `test_collect_names_covers_functions_methods_classes`, pure-function range assembly via a seam `ranges_from_series(series: list[tuple[str, bool]]) -> list[str]` — `test_contiguous_verified_series_become_one_range`, `test_gap_splits_ranges`, `test_unmatched_tag_series_excluded`; one git-backed test `test_verify_names_against_two_tags` (setUp repo where a function exists at `v1.0` but not `v1.1`).
- [ ] **Step 2: Run tests** — expected: ERROR, module missing.
- [ ] **Step 3: Implement `pipeline/verify.py`.**
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit.**

### Task 7: Record builder, confidence, cross-check, overrides — `pipeline/record.py`

**Files:**
- Create: `pipeline/record.py`, `data/overrides.json` (initial content `{}`)
- Test: `tests/test_record.py`

Modified by `docs/superpowers/plans/2026-11-04-review-folder.md` Task 1.

**Interfaces:**
- Consumes: merged advisory dicts; analysis results injected as plain dicts (no dependency on Tasks 5 or 9).
- Produces:
  - `PIPELINE_VERSION = "1"`
  - `commit_confidence(commit: dict) -> str` — `high` when `in_fixed_release` is True and not `bundle`; `medium` when the release check was unchecked or `bundle` is True.
  - `text_cross_check(summary_text: str, names: list[str]) -> dict` — `{"matched": [...], "unmatched_mentions": [...]}`; a mention is a `name()`-style token in the advisory text; a match raises that function's confidence per spec step 8.
  - `build_record(merged: dict, analysis: dict) -> dict` — `analysis` keys: `repo`, `fix_commits`, `rejected_commits`, `vulnerable`, `entry_points`, `names_verified_for`, `status`, `notes`. Output exactly the spec's record format plus `overrides_applied: []`, `pipeline_version`, `osv_modified` (= merged `modified`), `generated_at`.
  - `apply_overrides(record: dict, overrides: dict) -> dict` — overrides file format (per-ID): `status`, `fix_commits` (replace), `add_vulnerable` / `remove_vulnerable` (by name), `add_entry_points` / `remove_entry_points` (by name), `note`. Every applied operation appended to `overrides_applied`.
  - `write_record(record: dict, out_dir: Path) -> Path` — `<out_dir>/<id>.json`, sorted keys, trailing newline.
  - `write_index(records_dir: Path) -> Path` — reads every record in `records_dir` and writes `<records_dir>/index.json` mapping each record's `id` and every alias to the record's `id`; overwrites any existing index; returns the index path.

- [ ] **Step 1: Write failing tests**: `test_confidence_high_requires_release_check_and_no_bundle`, `test_confidence_medium_when_unchecked_or_bundle`, `test_text_cross_check_matches_and_records_misses` (`"idna.encode() is affected"` vs names containing `idna.core.encode` → matched; a mention matching nothing lands in `unmatched_mentions`), `test_cross_check_match_raises_function_confidence`, `test_build_record_matches_spec_shape` (assert the exact top-level key set from the spec example plus `overrides_applied`), `test_overrides_add_remove_and_mark_not_code`, `test_overrides_survive_rebuild` (apply to a freshly rebuilt record → same result), `test_write_record_path_and_roundtrip`, `test_write_index_maps_ids_and_aliases` (two records in a tmp dir → index keys cover both IDs and all aliases, values are record IDs).
- [ ] **Step 2: Run tests** — expected: ERROR, module missing.
- [ ] **Step 3: Implement `pipeline/record.py`.**
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit.**

### Task 8: Evaluation harness — `pipeline/evaluate.py`

Superseded by `docs/superpowers/plans/2026-11-04-review-folder.md` Task 4.

### Task 9: Entry points — `pipeline/entrypoints.py`

Superseded by `docs/superpowers/plans/2026-11-04-review-folder.md` Tasks 2–3.

### Task 10: Pipeline driver — `pipeline/run.py`

Superseded by `docs/superpowers/plans/2026-11-04-review-folder.md` Task 5.

### Task 11: Scan-side records and version check — `reachability.py` (part 1)

**Files:**
- Create: `reachability.py`
- Test: `tests/test_reachability.py`

**Interfaces:**
- Consumes: record JSON files and `index.json` (Task 7 shapes); `depscan.version_key`.
- Produces (stdlib only):
  - `load_db(db_dir: Path) -> dict` — reads `index.json` and returns `{"dir": db_dir, "index": {key: record_id}}` without opening any record file; when `index.json` is missing, builds the same index by scanning the record files instead; a missing or empty dir returns an empty index (reachability then reports unknown, it never crashes the scan). The fallback scan reads `db_dir/*.json` only and never `review/`; a record in `review/` is absent.
  - `record_for(finding: dict, db: dict) -> dict | None` — resolves `vulnerability_id`, then each of the finding's `aliases`, through the index (the design's alias-fallback rule), and loads `<dir>/<record_id>.json` on demand.
  - `version_in_ranges(version: str, ranges: list[str]) -> bool` — parses only the restricted `">=X, <Y"` form; compares with `depscan.version_key`; an unparseable specifier or version returns False (which downstream means unknown, the safe direction).
  - `project_python_files(root: Path) -> list[Path]` — every `*.py` under root, excluding directory names `.venv`, `venv`, `env`, `site-packages`, `node_modules`, `__pycache__`, and any dot-directory.
  - `scan_file(source: str, rel_path: str, targets: dict[str, str]) -> dict` — `targets` maps FQN → kind; returns `{"calls": [{"file": str, "line": int, "name": str}], "imports": [str], "star_imports": [str]}`. `calls` covers resolved calls **and** uses of class-kind targets (e.g. `Loader=yaml.FullLoader`); `imports` lists top-level modules imported; `star_imports` lists modules hit by `from x import *`. Spec import forms: `import yaml`, `import yaml as y`, `from yaml import full_load`, `from yaml import full_load as fl`, `from yaml.constructor import FullConstructor`.

- [ ] **Step 1: Write failing tests**: `test_load_db_reads_index_without_opening_records` (valid index beside a deliberately corrupt record file → `load_db` succeeds; `record_for` on the good record still works), `test_missing_index_falls_back_to_scanning_records`, `test_record_found_by_id_then_alias`, `test_no_record_returns_none`, `test_empty_db_dir_loads_empty`, `test_version_in_ranges_inside_and_outside`, `test_version_with_trailing_zero_in_range` (`"5.3.0"` inside `">=5.1, <5.4"`), `test_unparseable_specifier_is_false`, `test_project_files_exclude_venv_and_hidden` (writes a tmp tree with `app/x.py` and `.venv/lib/bad.py`), and for `scan_file`: `test_plain_and_aliased_imports_resolve`, `test_from_import_with_alias_resolves`, `test_class_target_used_as_argument_reported` (`yaml.load(f, Loader=yaml.FullLoader)` with `yaml.FullLoader` a class target → one call entry), `test_star_import_reported`, `test_unrelated_calls_ignored`.
- [ ] **Step 2: Run tests** — expected: ERROR, module missing.
- [ ] **Step 3: Implement `reachability.py`.**
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit.**

### Task 12: Statuses — `reachability.check_reachability`

**Files:**
- Modify: `reachability.py`
- Test: `tests/test_reachability.py` (extend)

**Interfaces:**
- Consumes: Task 11's functions; `scan_file` via module attribute (tests monkeypatch it for isolation; production uses Task 11's implementation).
- Produces: `check_reachability(findings: list[dict], project_root: Path, db_dir: Path) -> None` — adds to each finding: `reachability` (`"reachable"|"not_found"|"unknown"`), `reachability_reason` (one short sentence), `call_sites` (list, possibly empty). Rules, exactly as the spec's "Status for each finding":
  - Targets = record's `vulnerable` names + `entry_points` names (all confidences).
  - **reachable:** any call site matched, including medium-confidence entry points. All sites reported.
  - **not_found** requires every one of: record status `found`; ≥1 `high` vulnerable function; ≥1 `high` entry point; the project imports the package's top-level module somewhere; installed version inside `names_verified_for`; every project file parsed; no star-import of the package; no call found. Reason uses the Global Constraints verbatim copy.
  - **unknown:** everything else, with the first failing condition as the reason (e.g. `"no record for this advisory"`, `"transitive dependency, not imported directly"`, `"names not verified for this version"`, `"could not parse app/broken.py"`).

- [ ] **Step 1: Write failing tests** with a synthetic PyYAML-shaped record in a tmp db and monkeypatched `scan_file` outputs: `test_call_to_entry_point_is_reachable_with_sites`, `test_medium_entry_point_call_still_reachable`, `test_clean_project_is_not_found_with_verbatim_reason`, `test_no_record_is_unknown`, `test_not_code_record_is_unknown`, `test_only_medium_functions_is_unknown`, `test_no_high_entry_point_is_never_not_found` (Review Focus 5), `test_transitive_not_imported_is_unknown`, `test_version_outside_verified_ranges_is_unknown` (Review Focus 1), `test_unparseable_file_forces_unknown` (Review Focus 2 — monkeypatched `scan_file` raises `SyntaxError` for one file), `test_star_import_forces_unknown` (Review Focus 4), `test_call_inside_venv_ignored` (Review Focus 3 — the only "call" is in `.venv/`, result not_found-eligible, not reachable).
- [ ] **Step 2: Run tests** — expected: FAIL, `check_reachability` not defined.
- [ ] **Step 3: Implement `check_reachability`.**
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Commit.**

**Human gate 2:** the six review records must reach the main folder (signed overrides, see the review-folder plan Task 7) before Tasks 13 to 15 run.

### Task 13: CLI integration — `depscan.py`

**Files:**
- Modify: `depscan.py` (argparse, report, JSON writer), `README.md` (flag docs, experimental warning)
- Test: `tests/test_cli_reachability.py`

**Interfaces:**
- Consumes: `reachability.check_reachability`.
- Produces:
  - Flag `--experimental-reachability` and option `--db` (default `data/vulnfuncs`). Without the flag, behavior and output are byte-identical to v0.1 (no new fields, no new report lines).
  - With the flag: findings gain the three fields; the report sorts reachable findings first, then severity; each reachable finding's call sites print as `file:line  name`; each not_found finding prints the verbatim Global Constraints copy; the summary becomes `"{N} vulnerabilities in {M} packages, {R} reachable, {U} unknown"` (singular/plural words as v0.1).
  - JSON `resolution` block unchanged; the top level gains `"reachability_db"`: the db path, only when the flag ran.

- [ ] **Step 1: Write failing tests** driving `depscan.parse_findings`-shaped findings through the report/JSON paths directly (no osv-scanner): `test_without_flag_findings_have_no_reachability_fields`, `test_with_flag_fields_present_and_summary_line` (capture stdout, assert the exact summary string for 2 reachable / 1 unknown / 3 findings), `test_reachable_sorted_first_in_report`, `test_not_found_prints_verbatim_copy`, `test_json_gains_db_path_only_with_flag`.
- [ ] **Step 2: Run tests** — expected: FAIL.
- [ ] **Step 3: Implement** the flag plumbing in `main`, the report changes in `print_report`, the JSON addition in `write_json`; update README (flag table row, experimental note, the not_found wording).
- [ ] **Step 4: Run `python -m unittest`** — expected: all pass.
- [ ] **Step 5: Fixture check** (needs the real PyYAML record and index from Task 10's smoke run): `python depscan.py tests/fixtures/pyyaml_project --experimental-reachability`. Expected per the fixture README: reachable via `app/config_loader.py` (`yaml.full_load`), nothing from `app/settings.py`.
- [ ] **Step 6: Commit.**

### Task 14: Full PyPI run and coverage report

**Files:**
- Create: `data/vulnfuncs/` records for the full export; `docs/coverage-report.md`

- [ ] **Step 1: Gate.** Run `python -m pipeline.evaluate data/vulnfuncs data/handchecked` on the 28-advisory records. Proceed only on exit 0 (the accuracy bar); otherwise tune pipeline rules (the spec leaves confidence thresholds and tag patterns to the builder) and re-run — each tuning change is its own commit with the before/after numbers in the message.
- [ ] **Step 2: Full run:** `python -m pipeline.run --all --export data/osv --out data/vulnfuncs` (long; background it).
- [ ] **Step 3: Write `docs/coverage-report.md`:** counts of `found` / `unknown` / `not_code`, the evaluation numbers, and the ten most common `notes` reasons for `unknown`.
- [ ] **Step 4: Commit** (records plus report; if the records are too large for the repo, commit the report and open the publication question from the spec — "decided later" — with the owner).

### Task 15: Real-project headline

- [ ] **Step 1:** Clone a real FastAPI application (owner picks; default: the full-stack-fastapi-template example app) to the scratchpad and run `python depscan.py <app> --experimental-reachability`.
- [ ] **Step 2:** Verify every `reachable` call site by opening the file and line; verify a sample of five `not_found` and five `unknown` reasons are truthful.
- [ ] **Step 3:** Record the headline (`"N flagged, R reachable"`) and the verification notes in `docs/coverage-report.md`; commit. **Gate:** dropping the `--experimental-` prefix is a separate owner decision per the spec, not part of this plan.
