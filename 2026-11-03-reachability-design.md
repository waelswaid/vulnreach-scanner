# Reachability: design

Date: 2026-11-03
Status: ready for approval

## Why

depscan v0.1 flags every known vulnerability in a project's dependencies. Most
of those flags are noise: the project depends on the package but never runs
the vulnerable code. Reachability answers the question that matters: **does
this project's code actually call the vulnerable function?**

This is the gap the project exists to fill. pip-audit and Safety don't do it,
govulncheck does it only for Go, and the Python tools that do it are
commercial. The headline result should read like "24 flagged, 3 actually
reachable", and it must be trustworthy, because a wrong "not reachable" tells
someone to ignore a real vulnerability.

## The two problems

Reachability splits into two separate problems:

1. **Find the vulnerable code.** For each advisory, work out which functions in
   the affected package contain the vulnerability, by analysing the commit
   that fixed it. This is the same for every project, so it is done **once per
   advisory, offline**, and stored as a database of JSON records.
2. **Check whether a project calls it.** At scan time, for each finding depscan
   already produces, look up the advisory's record and search the project's
   source for calls to those functions.

```
                 offline, once per advisory                     at scan time
OSV PyPI advisories ──► [problem 1 pipeline] ──► records ──┐
                                                           ▼
project ──► depscan v0.1 (osv-scanner) ──► findings ──► [problem 2] ──► report + JSON
                                                           ▲
                                     project source code ──┘
```

Building problem 1 as an offline database (like Go's vulnerability database,
which already lists vulnerable functions) keeps scans fast and offline, lets
results be reviewed and corrected by hand, and makes coverage measurable.

## Goals

- For advisories with a usable fix commit, find the vulnerable functions
  accurately, with false positives filtered out.
- Mark every finding as **reachable**, **not found** or **unknown**, with file
  and line locations for reachable calls.
- Measure accuracy against a hand-checked set of correct answers, so changes
  can be judged by numbers rather than impressions.
- Later, cover advisories with no fix link by ranking commits in the diff
  between releases (phase B, below).

## Non-goals (for this design)

- Languages other than Python. The design keeps language-specific parts
  separate so others can be added later, but nothing else is built now.
- Full call-graph analysis of the project (calls through several layers of
  the project's own functions). The first version finds direct calls only.
- Vulnerable code in C extensions, Rust extensions or other non-Python files.
- Typosquatting, dependency confusion and CI exit codes. These are separate
  features in the overall plan.

## Anti-goals (failure even if it technically works)

- **Saying "not found" when the honest answer is "we don't know."** Any finding
  depscan can't analyse reliably is **unknown**. Never drop it, and never guess
  it down to "not found".
- Filling fields with guesses. The rule from v0.1 stands: a field is added only
  when it can be filled reliably. Reachability fields get added to findings in
  the version that actually fills them.
- Opaque answers. Every function in a record, and every reachability result,
  carries the evidence for it so a person can check it.

## Constraints

- Python only, for both the analysed packages and the scanned projects.
- Storage is JSON files, no database server (from the project plan).
- The scan side (problem 2) stays light: it must run offline and use only the
  Python standard library, like v0.1. *(My call.)*
- The offline pipeline (problem 1) may need network access, `git`, and extra
  libraries. It is a developer tool, not something end users run. *(My call.)*

## What the research found

These numbers come from the 28 Python advisories in our earlier scans
(PyYAML, requests, Jinja2, urllib3, idna, certifi). The design is built
around them.

- 19 advisories link a clean fix commit, 4 link misleading commits, and
  5 link no commit at all.
- The "FIX" label on OSV links can't be trusted. Only 17 of 28 advisories label
  any link as the fix, both PyYAML fixes are labelled as general web links,
  and one link labelled as the fix (idna) is just a release version bump.
- Kinds of misleading links seen: a release version bump with no fix in it;
  a release commit that bundles several fixes; an unrelated old refactor; a
  broader related change linked next to the actual fix.
- Inside clean fix commits, after dropping tests, docs and build files, most
  touch 1–2 code files and 1–3 functions. One outlier (urllib3's
  decompression fix) touches 13 functions, all part of the fix.
- The same fix is often committed to several branches (backports), and
  PyYAML keeps two copies of its code (`lib/` and `lib3/`).
- Git's diff headers (`@@ ... @@ def foo`) often name the wrong function, so
  functions must be found by parsing the code.
- In most advisories the fixed function is internal (PyYAML's
  `construct_python_object_new`, requests' `rebuild_proxies`), not the one
  users call (`yaml.full_load`, `requests.get`).
- For advisories with no fix link, the diff between the last vulnerable
  release and the fixed release gave up the fix in 3 of 4 cases. The clues
  were: small patch releases, GitHub's "Merge commit from fork" message on
  private security fixes, changelog files named after the GHSA ID, and CVE IDs
  in commit messages, sometimes a *different* CVE ID for the same bug.
- Some advisories aren't about code at all (certifi: bundled certificates).

The research scripts and raw data are in the session scratchpad. They are
throwaway and not part of the build.

---

## Part 1: the vulnerable code database (problem 1)

### Input

The full OSV export of PyPI advisories (one download from OSV). Each advisory
is processed on its own. Advisories that describe the same issue under
different IDs (GHSA, PYSEC, CVE) are merged into one, using OSV's aliases.
Each record is keyed by the GHSA ID when there is one, matching
`vulnerability_id` in depscan's findings. *(My call: it matches what v0.1
already outputs.)*

### Pipeline (phase A: advisories with fix links)

1. **Find the repository.** Take it from the advisory's version-range data
   (`GIT` ranges), its `PACKAGE` link, or the package's PyPI project links, in
   that order. Clone it locally, or update an existing clone. Local clones
   are used instead of the GitHub API because the API is rate-limited
   (60 requests an hour without a token), and the full pre-fix source is
   needed anyway.
2. **Collect candidate commits** from every source, ignoring link labels:
   - commits in `GIT` version ranges (`fixed` events);
   - commit links;
   - pull request links, resolved to their merge commit or commits;
   - compare links (`a...b`), resolved to the commits in that range.

   Links to hosts other than GitHub are recorded but not resolved in the first
   version. *(My call.)*
3. **Drop false positives.** A candidate commit is rejected when:
   - **It isn't in the fixed release.** It must be contained in the fixed
     version's release tag and *not* in the last vulnerable version's tag.
     This alone rejects unrelated old commits like the urllib3 refactor.
     Versions are mapped to tags by trying common patterns (`v1.2.3`,
     `1.2.3`, `<package>-1.2.3`). If no tag matches, the check is skipped and
     the result's confidence is lowered.
   - **It only bumps the version**, changing nothing but version strings,
     changelogs and docs (the idna case). If this leaves no candidates, the
     advisory moves to phase B.
   - **It's a release commit bundling several fixes** (the urllib3 1.24.2
     case). The candidate is kept but marked as a bundle, which caps
     confidence at medium. Splitting a bundle by matching the advisory text is
     phase B work.
4. **Merge duplicates.** Backports of the same fix to several branches, and a
   pull request together with its merge commit, become one fix. Functions are
   identified by fully qualified name (see step 6), so duplicate copies like
   PyYAML's `lib/` and `lib3/` merge automatically.
5. **Keep only library code.** Keep `.py` files inside the package's own
   import folder (for example `src/urllib3/`, `lib3/yaml/`). This drops tests,
   docs, build files and test helpers outside `tests/` (urllib3's
   `dummyserver/`).
6. **Find the changed functions.** Parse each changed file as it was *before*
   the fix using Python's `ast` module. Map each changed line to the innermost
   function or method containing it, and name it by fully qualified name:
   `yaml.constructor.FullConstructor.construct_python_object_new`.
   - **Modified function:** included.
   - **Function the fix adds:** excluded, since it didn't exist in the
     vulnerable version. It's recorded in the evidence.
   - **Function the fix deletes:** included.
   - **Only comments, docstrings or formatting changed:** excluded. This is
     detected by comparing the function's parsed code before and after,
     ignoring docstrings.
   - **Change at class or module level, outside any function:** recorded as a
     class-level or module-level change with its class or module name.
     Example: urllib3's fix changes the `Retry` class's default list of headers
     to remove on redirect.
7. **Check the names across the affected versions.** The names come from the
   code just before the fix, but a project may pin a much older affected
   version, where a function could live in another module or have another
   name. For each affected release series (the newest tag of each affected
   `major.minor`), check that every vulnerable name still exists there. Each
   record lists the version ranges where the names were confirmed
   (`names_verified_for`). At scan time, an installed version outside those
   ranges gets **unknown**, not "not found". *(My call: this is the only way to
   keep a stale name from turning into a false "not found".)*
8. **Use the advisory text as a cross-check.** Function or method names
   mentioned in the advisory (`idna.encode()`, `extract_zipped_paths()`) that
   match a changed function raise its confidence. A mention that matches
   nothing is recorded in the evidence.
9. **Find the public entry points** *(decided: done here, in the offline
   pipeline)*. Users rarely call the fixed internal function directly. PyYAML
   users call `yaml.full_load`, not `construct_python_object_new`. In the
   pre-fix source, build a call graph inside the package and walk it backwards
   from each vulnerable function to the **public** functions, methods and
   classes that can lead to it.
   - **Public** means importable without a leading underscore anywhere in its
     module path or name.
   - **Re-exports count.** `yaml.full_load` is defined in `yaml/__init__.py`,
     and `from yaml import FullConstructor` really means
     `yaml.constructor.FullConstructor`. The pipeline resolves each package's
     `__init__.py` imports, so every entry point is listed under every public
     name users can import it by.
   - Each entry point records the call path that leads to the vulnerable
     function, as evidence.

   The call graph inside a package has the same blind spots as any static
   analysis: dynamic dispatch, `getattr`, and calls through objects. An entry
   point found only through a guessed edge (for example, a method call matched
   by name alone) is marked `medium`. The resolution rules are the builder's to
   tune against the hand-checked set.
10. **Write the record** (below).

### Record format

One JSON file per advisory, for example `data/vulnfuncs/GHSA-8q59-q68h-6hv4.json`
*(location is my call)*:

```json
{
  "id": "GHSA-8q59-q68h-6hv4",
  "aliases": ["CVE-2020-14343", "PYSEC-2021-142"],
  "package": "pyyaml",
  "ecosystem": "PyPI",
  "repo": "https://github.com/yaml/pyyaml",
  "status": "found",
  "fix_commits": [
    {"sha": "a001f2782501ad2d24986959f0239a354675d0a6", "source": "web_link",
     "in_fixed_release": true, "bundle": false}
  ],
  "rejected_commits": [],
  "vulnerable": [
    {"name": "yaml.constructor.FullConstructor.construct_python_object_new",
     "kind": "function", "file": "lib3/yaml/constructor.py",
     "confidence": "high",
     "evidence": ["modified in a001f27", "body changed, not cosmetic"]},
    {"name": "yaml.constructor.FullConstructor.set_python_instance_state",
     "kind": "function", "file": "lib3/yaml/constructor.py",
     "confidence": "high", "evidence": ["modified in a001f27"]}
  ],
  "entry_points": [
    {"name": "yaml.full_load", "defined_as": "yaml.full_load",
     "confidence": "high",
     "path": ["yaml.full_load", "yaml.load", "…",
              "yaml.constructor.FullConstructor.construct_python_object_new"]},
    {"name": "yaml.FullLoader", "defined_as": "yaml.loader.FullLoader",
     "confidence": "high", "path": ["…"]}
  ],
  "names_verified_for": [">=5.1, <5.4"],
  "pipeline_version": "1",
  "osv_modified": "2024-…",
  "generated_at": "2026-…"
}
```

Field values:

- **`status`:**
  - `found`: at least one vulnerable function or class-level change identified
  - `unknown`: no usable fix found, or analysis failed; the reason goes in `notes`
  - `not_code`: the vulnerability isn't in Python code, for example bundled data like certifi's certificates, or a C extension
- **`kind`:** `function`, `method`, `class_level` or `module_level`.
- **`confidence`:**
  - `high`: from a commit that passed the release check, isn't a bundle, and the function isn't cosmetic
  - `medium`: the release check was skipped (no tag matched), or the commit is a bundle
  - `low`: phase B results without a strong clue

The exact rules are the builder's to tune against the hand-checked set.

### Overrides

A hand-written overrides file can correct any record: add or remove
functions, mark an advisory `not_code`, or pin the fix commit. Overrides are
applied after the pipeline runs and recorded in the record's evidence, so
regenerating the database never loses a hand correction. This replaces the
"small hand-made mapping" in the original plan.

### The hand-checked set and measuring accuracy

Before building the pipeline, write down the correct answer for each of the
28 research advisories: the true fix commit(s) and the true vulnerable
functions. It deliberately includes the known tricky cases: the idna release
bump, the unrelated urllib3 refactor, the urllib3 1.24.2 bundle, PyYAML's two
commits and two code copies, and certifi as `not_code`.

Every pipeline run reports against this set:

- functions found correctly;
- wrong functions added (false positives);
- functions missed (false negatives);
- advisories whose status is wrong.

The pipeline is run on the full PyPI export only after it scores well here.
The full run then reports coverage: how many advisories end up `found`,
`unknown` and `not_code`.

### Phase B: advisories without fix links (after phase A works)

Phase B is described here so the record format leaves room for it, but it is
**planned and built separately** after phase A and problem 2 work. The plan
for this design stops after build step 7. *(My call: its tooling is still
undecided and needs its own evaluation.)*

This phase handles advisories that phase A leaves without a usable commit. It
adds one step before "drop false positives":

1. Take every commit between the last vulnerable release tag and the fixed
   release tag.
2. Rank them by these clues:
   - the advisory's ID, or *any* alias (including related CVE IDs from other
     trackers), in the commit message;
   - a changelog file named after the advisory;
   - the "Merge commit from fork" message;
   - function names from the advisory text among the commit's changed
     functions;
   - the commit's size (small patch releases make this easy).
3. Treat the top candidates as fix commits, with confidence capped at medium
   when a strong clue such as an ID or a GHSA changelog file matched, and low
   otherwise.

Using an AI model to rank candidates for the hardest cases, and Prospector
(SAP's project-kb tool, which ranks candidate fix commits), are both worth
evaluating at the start of phase B, but neither is decided.

### Keeping the database fresh

Re-running the pipeline only reprocesses advisories whose OSV `modified` date
changed or whose `pipeline_version` is older than the current one. How the
database is published with depscan (in the repo, as a separate download, and so
on) is decided later.

---

## Part 2: checking the project's code (problem 2)

### Input

- The findings depscan v0.1 already produces.
- The vulnerability database records, looked up by `vulnerability_id` first,
  then by the finding's aliases. Records are keyed by GHSA ID, but a finding
  with no GHSA falls back to the first ID osv-scanner lists (v0.1 behaviour),
  which can differ between osv-scanner versions and databases. Both the
  finding and the record carry aliases, so matching through them keeps such a
  finding from becoming "unknown — no record" when a record exists.
- The scanned project's Python source files.

### Analysis (first version: direct calls only)

For each Python file in the project:

1. Parse it with `ast`.
2. Track imports and aliases:
   - `import yaml`
   - `import yaml as y`
   - `from yaml import full_load`
   - `from yaml import full_load as fl`
   - `from yaml.constructor import FullConstructor`
3. Find every call (and every use of a listed class, such as passing
   `Loader=yaml.FullLoader`), resolve its name through those imports to a
   fully qualified name, and compare it with the record's vulnerable
   functions **and** its entry points.

Analysis is limited to code in the scanned folder, excluding virtual
environments and installed packages.

### Status for each finding

- **reachable:** at least one call to a vulnerable function or entry point
  found. Report every call site with file and line. A call that matches only a
  `medium` confidence entry point still counts as reachable: a wrong
  "reachable" makes someone look, a wrong "not found" makes them look away.
- **not found:** the record is `found` with at least one `high` confidence
  function **and** at least one `high` confidence entry point, the package's
  code can be matched to the project's imports, and no call was found. This is
  worded in the report as "no call found", never as "safe". Silence against
  guessed-edge (`medium`/`low`) entry points proves nothing, so a record
  without a `high` entry point can never produce "not found".

  *Decided:* "not found" means **the project's own code** makes no call to the
  vulnerable code. It does not rule out another dependency calling it. For
  example, a project that imports urllib3 and also uses requests may still
  reach the vulnerable urllib3 code through requests. Checking that would need
  the full dependency graph, which osv-scanner doesn't give. The report must
  say this plainly next to every "not found", for example "no call from your
  code; calls from other packages were not checked".
- **unknown:** everything else, including:
  - no record exists, or its status is `unknown` or `not_code`;
  - the record has only `medium`/`low` functions, or only `medium`/`low`
    entry points *(my call; the builder may revisit once accuracy numbers
    exist)*;
  - the package is a **transitive dependency** the project doesn't import
    itself. For example, the urllib3 vulnerabilities in a project that only
    imports requests: requests may call the vulnerable urllib3 code, and
    direct-call analysis can't see that. *(My call: anything else would break
    the "never guess down to not found" rule.)*

### Output

Findings gain these fields, only in the version that fills them:

- `reachability`: `reachable`, `not_found` or `unknown`;
- `reachability_reason`: one short sentence, for example "no record for this advisory" or "transitive dependency, not imported directly";
- `call_sites`: a list of file, line and called name.

The terminal report sorts reachable findings first, then by severity, and the
summary line gains the headline number, for example
"21 vulnerabilities in 4 packages, 2 reachable, 15 unknown".

Reachability runs only with an `--experimental-reachability` flag until the
accuracy bar (below) is met. Without the flag, depscan behaves exactly like
v0.1.

### Known limits of the first version

- Calls through the project's own wrapper functions are missed.
- Calls on objects are mostly missed (`session.get(...)` on a
  `requests.Session` instance needs type information).
- Dynamic imports and `getattr` are missed.
- Missed entry points in the package's own call graph (see Part 1, step 9)
  mean missed reachable calls. Those are counted in the accuracy numbers.

These limits are why `unknown` is the default whenever there's doubt.

---

## Decisions

1. **Connecting internal functions to public ones:** done in the offline
   pipeline (Part 1, step 9). Each record lists public entry points, including
   re-exported names. Handling it at scan time was rejected because the scan
   side can't see installed packages. Hand overrides alone were rejected
   because they don't scale.
2. **"Not found" means no call from the project's own code.** Calls from
   other dependencies aren't checked, and the report says so (Part 2).
3. **Who writes what:**
   - **The project owner writes the reachability core by hand:**
     - finding the changed functions (Part 1, step 6);
     - finding the entry points (Part 1, step 9);
     - matching imports, aliases and calls at scan time (Part 2, analysis).
   - **Claude Code writes the rest:** commit collection, the release check,
     filters, the record writer, the overrides file, the scan-side plumbing
     and output, test scaffolding, and reviews of the owner's code.
   - **The hand-checked set:** Claude Code drafts the correct answers for the
     28 advisories with evidence for each. The project owner checks and signs
     them off before any pipeline code is written, so the accuracy numbers
     don't just check Claude Code against its own answers.

   For the parts the owner writes, the plan provides the interfaces, data
   shapes and tests, not the implementation.
4. **Accuracy bar,** measured on the hand-checked set:
   - **Functions found:** at least 90% of the true vulnerable functions (recall ≥ 90%).
   - **Wrong functions:** at most 1 in 10 of the reported functions is wrong (precision ≥ 90%).
   - **Entry points found:** at least 95% of the true entry points (recall ≥ 95%).
     This is the strictest number on purpose: a missed vulnerable function
     mostly degrades a finding to `unknown`, but a missed entry point turns
     directly into a false "not found" — the failure the anti-goals forbid.
   - **Statuses:** every `not_code` and `unknown` status is correct.

   The full PyPI run (build step 6) happens only after the pipeline meets this
   bar. Reachability stays behind `--experimental-reachability` until the full
   pipeline, including entry points, meets it.

## Build order

Steps marked *(owner)* are written by the project owner. For those, the plan
supplies interfaces and tests.

1. **Hand-checked set:** Claude Code drafts the correct answers for the 28
   research advisories, and the owner signs them off. Each answer covers the
   true fix commit(s), the vulnerable functions and the expected entry points.
2. **Pipeline core:** run it on one advisory end to end. Collect commits,
   apply the release check, filter files, find functions *(owner)*, write a
   record.
3. **Remaining phase A rules** (version bumps, bundles, duplicates, cosmetic
   changes, class-level changes, the version-range name check, the
   advisory-text cross-check), measured against the hand-checked set after
   each rule.
4. **Entry points** *(owner)* and the **overrides file**.
5. **Problem 2 scan side:** imports, aliases and calls *(owner)*, then
   statuses and output behind `--experimental-reachability`, tested on
   `tests/fixtures/pyyaml_project/`.
6. **Full PyPI run** and the coverage report.
7. **A real project** (a FastAPI app) for the headline number.

Phase B follows in a separate plan.

The PyYAML test project already has the expected answer:
- `app/config_loader.py` calls `yaml.full_load` and should be reported as reachable.
- `app/settings.py` only calls `yaml.safe_load` and should not be reported.

This test passes only once the entry points work (build step 4), because
`yaml.full_load` is the public entry point and not the function the fix
changed.

## Left to the builder

- Code layout: whether depscan stays one script or becomes a package now that
  there are several parts. The project plan's library-first design (`scan()`
  returning findings, CLI as a thin wrapper) is the target, but the timing is
  open.
- Exact confidence rules and thresholds, tuned against the hand-checked set.
- Version-to-tag matching patterns, and how repositories are cached.
- Which libraries the offline pipeline uses.
- The overrides file format.
