# Review folder for records without derivable entry points: design

Amends `2026-11-03-reachability-design.md` (Part 1, step 9 and "Overrides")
and the phase A plan (Tasks 7, 8, 9, 10, 11). Decided with the owner on
2026-11-04.

## Why

The entry-point walker (step 9) builds a call graph inside the package and
walks backwards from each vulnerable function to public names. Four of the
ten hand-checked advisories have vulnerable code that no call edge leads to:

| File | Package | Why the walk finds nothing |
| --- | --- | --- |
| GHSA-h75v-3vvj-5mfj | jinja2 | `do_xmlattr` is a value in the `FILTERS` dict; compiled template code looks it up by string. |
| GHSA-cpwx-vrp4-4pq7 | jinja2 | `do_attr`, same table. |
| GHSA-6757-jp84-gxfx | pyyaml | `set_python_instance_state` has two callers, but both are registered through `add_multi_constructor(tag, func)` and dispatched from a dict lookup in `construct_object` (`lib3/yaml/constructor.py:85`, `:102`). The chain dead-ends one hop up. |
| GHSA-8q59-q68h-6hv4 | pyyaml | Only module-level code changed; there is no function node to walk from. |

A fifth, GHSA-gmj6-6f8f-6699, reaches `visit_FromImport` only through
`getattr(self, "visit_" + ...)`: no caller, no reference anywhere.

"Registered in a table, called by lookup" is the common shape in this set,
not a Jinja oddity. A walker that returns nothing for these records makes
them look finished when they are not, and a record whose only entry point is
the vulnerable function itself turns into a false "no call found" for every
project that uses the package. That is the failure the anti-goals forbid.

**The owner's decision: the strict walker.** The walker follows only call
edges it can resolve to a definition. It never invents an edge from a value
reference, a registration call or a name pattern. Everything it cannot
connect to a public name goes to a review folder, and the owner resolves each
case by hand in the overrides file. Fewer guessed edges in records, more
review work. The alternative (medium-confidence edges from registrations,
review folder for the rest) was considered and rejected.

## Goals

- A record with any vulnerable item the walker could not connect to a public
  name never reaches the main records folder, so the scan side can never
  report "no call found" against it.
- Every record in the review folder says, in the record itself, why it is
  there and where in the package source to look.
- Resolution is a hand-written override with a written reason. After a
  rerun, the record moves to the main folder and keeps the reason.
- The evaluator shows which records are in review and why, so the owner
  can see the queue and the progress through it.

## Non-goals

- Guessing edges from dict literals, registration calls, decorator
  arguments or `visit_*`-style name patterns (rejected by the owner).
- Changing the scan side's statuses. A record that is not in the main folder
  is treated as absent, which already yields `unknown`.
- Phase B advisories.

## Anti-goals

- A record that is silently counted as resolved: a stale copy left in one
  folder after the other folder received the fresh record.
- A hand edit to a file in the review folder. The next run overwrites it.
  The record must say so in its own text.
- A review reason that names the function but not the place to look.
- A resolution with no written reason. A hand override that moves a record
  out of review without a note is the kind of unexplained hand-mapping the
  original design rejected.

## Constraints

Those of the phase A plan: pipeline is stdlib Python plus `git`; storage is
JSON files; `data/vulnfuncs/index.json` covers the main folder and the scan
side opens only the index and the records its findings need; `python -m
unittest` stays green after every task.

## The design

### 1. Where records go

- Main folder: `data/vulnfuncs/<ID>.json`, unchanged.
- Review folder: `data/vulnfuncs/review/<ID>.json` *(my call: a subfolder
  of `--out` keeps the database self-contained; a sibling folder would work
  the same way)*.

Rules:

- `record.write_index` indexes the main folder only. It must not descend
  into `review/`. The scan side's `load_db` fallback (scanning record files
  when the index is missing) must not descend either.
- Every run writes exactly one copy of each advisory's record and deletes
  the copy in the other folder if one exists.
- Nobody edits a file in `review/`. The record carries the sentence
  "Do not edit: resolve in data/overrides.json and rerun" in its `review`
  field.

### 2. What the walker produces

The walker's inputs stay as planned: the pre-fix package source and the
vulnerable items. Its edges are:

- `high`: a call the walker resolves to a definition in the package: a
  module-level function called by name or through a resolved import;
  `self.m()`, `cls.m()` and `ClassName.m()` resolved to a method; and
  `ClassName(...)` as a call to that class's `__init__` (walking up through
  base classes defined in the package).
- `medium`: a method call on an object whose class the walker cannot
  resolve, matched by method name alone. Unchanged from the plan.
- **No edge** from a function or method name used as a value: in a dict,
  list, tuple or set literal; as an argument to any call (`add_multi_constructor(tag, func)`,
  decorators with arguments); on the right-hand side of an assignment; as a
  default argument; as a return value. No edge from names built at runtime
  (`getattr`, string concatenation, `__getattr__`). Nothing else is guessed.

Besides the entry points, the walker reports every vulnerable item it could
not connect, with a reason. "Connected" is decided at the **roots** of the
backward walk, not at the first public name met on the way:

1. From each vulnerable item, take the full backward closure over `high`
   and `medium` edges.
2. A **root** is a function or method in that closure with no resolved
   caller.
3. A root is **clean** when it is public and its name is not used as a
   value anywhere in the package. A root that is referenced as a value is a
   registration, and the chain through it is a dead end.
4. The item is connected when at least one root **other than the item
   itself** is clean. Every public name on a chain from a clean root to the
   item is an entry point, as before. Public names on dead-end chains are
   still written to `entry_points` with the confidence their edges give (a
   direct call to them does reach the item), but they do not count as
   connecting.

A public intermediate does not connect. `FullConstructor.construct_python_object`
is public and calls `set_python_instance_state`, but it is a root that
`add_multi_constructor` references, so the chain is dead.

A clean root may be a method. Nothing in Jinja calls `Template.render` or
`Environment.from_string`; they are roots with no reference, and they are the
package's API. Treating method roots as unclean would send every record of a
class-based package to review, which is most of PyPI. *(Owner's decision,
2026-11-04; see "Decisions" at the end.)*

The reasons:

| Kind | When | What the record carries |
| --- | --- | --- |
| `referenced_not_called` | The item has no resolved caller and its name appears as a value somewhere in the package. | Each reference: file, line, and the context in words ("value in dict literal FILTERS", "argument to add_multi_constructor"). |
| `no_reference` | The item has no resolved caller and no reference anywhere in the package. | The item's kind (function or method) and defining file. |
| `dead_end_chain` | The item has callers, but every backward chain ends at a function that is itself `referenced_not_called` or `no_reference` before reaching a public name. | Each dead-end function with its own references, so the owner sees where the chain stops. |
| `module_level` | The vulnerable item is a module, not a function. | The module's file. |
| `class_level` | The vulnerable item is a class body (changed class attributes) on a **private** class. | The class's file. |

Every reason also names the vulnerable item it is about.

A `class_level` item on a **public** class is connected by the class itself:
the class is its entry point, as `yaml.FullLoader` is today, and no reason is
raised. Classes are passed around as values all the time (`Loader=FullLoader`),
so the value-reference test does not apply to them. The walker does not try
to turn instantiations or subclassing into edges for class-level data in
phase A. *(My call; no phase A truth file has a `class_level` item, and
urllib3's `Retry` is the first one expected.)*

**The item as its own root.** When the only root is the vulnerable item
itself (nothing in the package calls it), the walker has found no chain at
all, and the rule is stricter than for a chain's root:

- a public **module-level function** with no reference anywhere is treated
  as a top-level API that users call directly, like `yaml.full_load`. It is
  its own entry point, the record goes to the main folder, and the record
  notes "self-only entry point: no caller or reference inside the package".
  Without this, every advisory whose vulnerable function is a plain API
  function would land in review. *(My call; the owner may remove it.)*
- a **method** with no caller and no reference (`visit_FromImport`,
  `SandboxedEnvironment.call`) goes to review as `no_reference`. The
  asymmetry with clean method roots is deliberate: a method root at the top
  of a real chain has shown the walker outgoing calls that lead somewhere,
  while a changed method that nothing reaches is as likely a dispatch target
  as an API, and the record would otherwise carry that method as its only
  entry point, which is the false "no call found" the anti-goals forbid.
- anything referenced as a value goes to review as `referenced_not_called`.

Expected first-run outcome on the ten truth files: six in review.
GHSA-6757-jp84-gxfx (`dead_end_chain`), GHSA-8q59-q68h-6hv4 (`module_level`),
GHSA-h75v-3vvj-5mfj and GHSA-cpwx-vrp4-4pq7 (`referenced_not_called`),
GHSA-gmj6-6f8f-6699 (`no_reference`), and GHSA-q2x7-8rv6-6q7h, whose
`SandboxedEnvironment.call`, `getattr` and `getitem` are called only from
generated template code (`no_reference`, or `dead_end_chain` through the
filter table for `getitem`). The builder confirms the other four reach the
main folder; any that do not are either a walker bug or a seventh case to add
to this table.

### 3. The record

A new top-level field, `review`, in every record:

```json
"review": {
  "status": "open",
  "tree": "48b0687ec0ca7f63f1d8f9b5c8a3ab6a0bbf7a3e",
  "reasons": [
    {"item": "jinja2.filters.do_attr",
     "kind": "referenced_not_called",
     "references": [
       {"file": "src/jinja2/filters.py", "line": 1825,
        "context": "value in dict literal FILTERS"}
     ]}
  ],
  "resolve": "Do not edit: resolve in data/overrides.json and rerun"
}
```

- `status` is `open` (record is in the review folder), `resolved` (the
  owner resolved every reason through the overrides file; record is in the
  main folder; `reasons` is kept so the next reader knows why the entry
  points are hand-written) or `none` (the walker connected every item;
  `reasons` is empty).
- `tree` is the commit the walker analysed (the fix commit's first parent),
  so the file and line numbers in the reasons refer to a tree the reviewer
  can check out.
- For `dead_end_chain`, each reason carries `dead_ends`: a list of
  `{"name", "references"}` in the same shape as above.
- For `module_level` and `no_reference`, `references` is empty and `file`
  names the defining file.

Records with status `unknown` or `not_code` have no vulnerable items, so
their `review.status` is `none` and they go to the main folder as before.

### 4. Resolving a case

The owner reads the reasons, opens the package source at the referenced
lines, works out the public names that lead to the item, and writes an
override. Two new override keys, alongside the existing ones:

- `reviewed`: a list of vulnerable item names whose review reasons the owner
  has settled, or `true` for all of them.
- `note` becomes **required** whenever `reviewed` is set. The pipeline
  refuses (a `PipelineError` naming the advisory) an override that marks
  items reviewed without a note. The note is the owner's evidence: which
  path reaches the item and how they confirmed it.

The usual `add_entry_points` entries supply the names. Their `path` should
end at the vulnerable item so the record's evidence reads like a walker
result; the pipeline does not enforce this.

A record goes to the main folder when, after overrides, every open reason's
item is covered by `reviewed`. Otherwise it stays in review, including when
some items are reviewed and others are not. Marking an item reviewed without
adding entry points is allowed (the owner has confirmed the item is its own
entry point); the note must say so. A `reviewed` name with no open reason is
recorded in `overrides_applied` and changes nothing.

**Overrides apply in two passes.** Today `apply_overrides` runs on the
finished record, so a hand-added vulnerable item would never be walked: no
entry points, no reason, `confidence: high`, and a clear path to the main
folder for an item the walker never saw. Instead:

- before the walk: `status`, `fix_commits`, `add_vulnerable`,
  `remove_vulnerable`. The walker then sees the corrected item list, and a
  `remove_vulnerable` drops any reason the item would have raised.
- after the walk: `add_entry_points`, `remove_entry_points`, `reviewed`,
  `note`.

Both passes append to `overrides_applied` as now. How `process_advisory`
and `apply_overrides` are shaped to do this is the builder's choice.

**Who writes the overrides** *(owner's decision, 2026-11-04)*: the builder
drafts them, the owner signs them off, as Task 1 did for the truth set. Each
override entry that carries `reviewed` also carries `signed_off`, `false`
when drafted. Until the owner flips it to `true`:

- the entry's `add_entry_points`, `remove_entry_points` and `note` apply as
  usual, so the drafted record can be read in full;
- `reviewed` does not take effect, so the record stays in the review folder,
  and `overrides_applied` says "reviewed: not applied, unsigned".

`signed_off` gates only `reviewed`. The other override operations keep
working without it, as they do today: the sign-off is the one human judgment
this design adds, not a review of every hand correction. The drafted note is
the builder's claim until signed; the owner checks it against the package
source at the record's `tree` before flipping the flag.

Example for GHSA-cpwx-vrp4-4pq7:

```json
"GHSA-cpwx-vrp4-4pq7": {
  "reviewed": ["jinja2.filters.do_attr"],
  "add_entry_points": [
    {"name": "jinja2.sandbox.SandboxedEnvironment",
     "defined_as": "jinja2.sandbox.SandboxedEnvironment",
     "path": ["jinja2.sandbox.SandboxedEnvironment",
              "jinja2.Environment.__init__ (self.filters = DEFAULT_FILTERS.copy())",
              "compiled template: environment.filters['attr']",
              "jinja2.filters.do_attr"]},
    {"name": "jinja2.sandbox.ImmutableSandboxedEnvironment", "...": "..."},
    {"name": "jinja2.Environment.call_filter", "...": "..."}
  ],
  "note": "do_attr is only referenced from FILTERS; it runs from compiled template code (compiler.py pull_dependencies) or Environment.call_filter. Exposure is sandbox-only, so plain Environment is not listed. Checked against tag 3.1.5 on 2026-11-04."
}
```

### 5. The driver

`process_advisory` writes the record to the folder its `review.status`
selects and removes the other folder's copy. A record found in both folders
before a run is a leftover from an interrupted run: the driver treats the
advisory as stale and reprocesses it; the evaluator and `write_index` refuse
with an error naming the ID rather than pick one.

Freshness: the existing rule skips an advisory whose record has the same
`osv_modified` and `pipeline_version`. Writing an override must make the next
run reprocess that advisory without `--force`, or the review loop needs a
manual step every time. Each record therefore also stores
`overrides_fingerprint`: a SHA-256 of the advisory's override spec serialised
with sorted keys, or `null` when there is none. The freshness check compares
it too, and looks for the existing record in both folders. *(My call: the
alternative is to document "rerun with `--force --advisory ID`" as the
resolution step, which is one more thing to forget.)*

### 6. The evaluator

`evaluate` reads both folders. Each record is scored exactly as before, so a
record in review with missing entry points lowers entry-point recall: the
bar is for the finished database, and an unresolved review case is a gap in
it. The per-advisory table gains a column showing `review.status` and the
reason kinds, and the summary prints the count in review. A record in review
is not a wrong status.

### 7. The scan side

Unchanged, apart from the folder rule in section 1. A record in review is
absent as far as the scan side is concerned, and the finding is `unknown`
with the existing reason "no record for this advisory". *(Optional, builder's
call, low priority: if `review/<ID>.json` exists, use the reason "record
under review" instead. The scan side must not read anything else from that
file.)*

### 8. The hand-checked set

Unchanged. Files 7 and 9 already list the override-supplied entry points and
say in their evidence that they come from the overrides file. The first run
fails entry-point recall on the review cases; the run after the owner writes
the overrides is the one measured against the bar.

### 9. Amendments to the existing documents

To be folded in when the plan is written:

- `2026-11-03-reachability-design.md`, step 9: replace the paragraph about
  guessed edges with the strict rule and the review folder; add Decision 5
  ("strict walker, review folder, overrides with a required note").
- Phase A plan, Task 7: the `review` field, `overrides_fingerprint`, the two
  new override keys, the required note, the two-pass override order, and a
  `PIPELINE_VERSION` bump for the new record shape.
- Task 8: both folders, the review column and count.
- Task 9: the reference collection, the reason kinds, the exemption, and the
  interface change (the walker returns entry points **and** the unconnected
  items; whether that is one function returning a dict or two functions is
  the builder's choice).
- Task 10: folder routing, stale-copy removal, fingerprint in freshness.
- Task 11: `load_db` fallback ignores `review/`.
- Task 10's golden-advisory smoke run (GHSA-8q59-q68h-6hv4) now expects the
  record in `review/` with a `module_level` reason, not in the main folder.
- A new task after Task 10: run the ten truth advisories, draft an override
  with a note for every record in `review/` (expected six), each with
  `signed_off: false`, and stop. The plan's second human gate: the owner
  signs the overrides off. Task 13's fixture check, Task 14's accuracy gate
  and Task 15 run only after the six records have reached the main folder.

## What the builder should test

Against the fake package in `tests/test_entrypoints.py`, extended:

- A function that is a value in a module-level dict and has no caller →
  `referenced_not_called` with the dict's file and line.
- A method passed as an argument to a classmethod call (`Cls.register(tag,
  Cls.method)`) → `referenced_not_called` naming the call.
- A public function whose only caller is such a registered function →
  `dead_end_chain` listing the dead end and its reference.
- A `module_level` item → `module_level`.
- A public module-level function with no caller and no reference → not in
  review, its own entry point, the "self-only" note present.
- A public method with no caller and no reference → `no_reference`.
- A function reached through a `medium` edge only → not in review (the
  existing never-not-found rule handles it at scan time).

For the driver and overrides:

- An open record is written to `review/` and a stale main-folder copy is
  deleted; a resolved record the other way round.
- `reviewed` without `note` → `PipelineError` naming the advisory.
- `reviewed` covering only some open items → record stays in review.
- `reviewed` with `signed_off: false` → entry points added, record stays in
  review, `overrides_applied` says so; flipping to `true` moves it.
- A changed override spec makes the freshness check reprocess the advisory.
- `write_index` and `load_db` ignore `review/`.

For the evaluator: a record in review is scored, shown in the review column,
and counted in the summary.

## Left to the builder

- Function names and signatures for the walker's second output.
- How references are collected: one pass over the package's AST that
  records every `Name` or `Attribute` node resolving to a package
  definition and not in call position, with its enclosing construct for the
  context text.
- The exact wording of context strings, beyond the examples above.
- Whether `review.reasons` for a `resolved` record also lists which override
  entries resolved it, or relies on `overrides_applied`.
- The order of columns in the evaluator's table.

## Decisions (owner, 2026-11-04)

Raised by the builder check and settled by the owner.

1. **Strict walker, review folder.** No edges from value references,
   registrations or name patterns. Unconnected items send the record to
   `review/`; the owner resolves them through the overrides file with a
   required note.
2. **Clean method roots.** A chain may end at a public method that nothing
   calls or references (`Template.render`) and count as connected. A
   *vulnerable* method with that profile still goes to review. The fully
   strict alternative (every such root is a dead end) was rejected because
   it sends every Jinja record and most class-based packages to review; the
   looser one (a vulnerable method root is its own entry point) was rejected
   because it puts GHSA-gmj6-6f8f-6699 in the main folder with
   `visit_FromImport` as its only entry point.
3. **Builder drafts the overrides, owner signs them off.** A per-entry
   `signed_off` flag gates `reviewed` only (section 4). The plan gains a
   drafting task after Task 10 and a second human gate before Tasks 13 to 15.
