# Hand-checked truth set

One JSON file per advisory, holding the correct answer the reachability
pipeline is measured against (design: `2026-11-03-reachability-design.md`,
"The hand-checked set and measuring accuracy"). Each answer was drafted by
reading the advisory, the upstream repository and the fix commit, and is
signed off by the project owner before any pipeline code is judged against it.

## Scope

The phase A set is **10 advisories**, chosen so that every rule the phase A
pipeline must implement is exercised at least once, and so that phase A can
solve every one of them (each has a usable fix link in OSV):

| # | File | Package | What it exercises |
| --- | --- | --- | --- |
| 1 | GHSA-6757-jp84-gxfx | pyyaml 5.3.1 | A linked commit that *introduced* the vulnerable feature; the release check must reject it. Fix mirrored in `lib/` and `lib3/`. Added methods excluded. |
| 2 | GHSA-8q59-q68h-6hv4 | pyyaml 5.4 | Module-level-only fix (constructor registrations move). The CVE the test fixture `tests/fixtures/pyyaml_project` depends on. |
| 3 | GHSA-x84v-xcm2-53pg | requests 2.20.0 | Pull-request link resolved to its merge commit. |
| 4 | GHSA-j8r2-6x86-q33q | requests 2.31.0 | Clean one-line fix; entry points through the redirect chain. |
| 5 | GHSA-9hjg-9r4m-mvj7 | requests 2.32.4 | Vulnerable function in `utils`, reached through `Session.prepare_request`. |
| 6 | GHSA-q2x7-8rv6-6q7h | jinja2 3.1.5 | Deleted functions count as vulnerable; "Merge commit from fork". |
| 7 | GHSA-h75v-3vvj-5mfj | jinja2 3.1.4 | A function plus a substantive module-level change (the regex). Entry points through the filter table: the render API. |
| 8 | GHSA-gmj6-6f8f-6699 | jinja2 3.1.5 | Two-parent commit where `git show` prints nothing; entry points via the `Environment` compile chain. |
| 9 | GHSA-cpwx-vrp4-4pq7 | jinja2 3.1.6 | Single function, clean; sandbox exposure. Entry points through the filter table: the sandbox classes only. |
| 10 | GHSA-248v-346w-9cwc | certifi 2024.7.4 | `not_code`, with a linked commit that also bumps a `.py` version string. |

`deferred/` holds 18 more drafted answers (the rest of pyyaml, requests,
jinja2, idna and certifi). They are not read by the evaluator. They are
deferred because phase A cannot solve them by design, or because the answer
involves a judgment call that is better settled once the pipeline exists:

- **No fix link in OSV** (phase B work): GHSA-3pqx-4fqf-j49f, GHSA-cfj3-7x9c-4p3h,
  GHSA-652x-xj99-gmcc, GHSA-8r7q-cvjq-x353, GHSA-462w-v97r-4m45,
  GHSA-65pc-fj4g-8rjx, GHSA-6q48-6c7w-9gw2.
- **Only link is the version bump** (phase A correctly answers "unknown"):
  GHSA-jjg7-2v4v-x38h.
- **Judgment calls** (see each file's `notes`): GHSA-9wx4-h78v-vm56,
  GHSA-rprw-h62v-c2w7, GHSA-hj2j-77xm-mc5v, GHSA-fqh9-2qgg-h84h.
- **Plain extras**, cut for size: GHSA-pg2w-x9wp-vw92, GHSA-gc5v-m9x4-r6x2,
  GHSA-g3rq-g295-4j3m, GHSA-h5c8-rqwp-cp95, GHSA-43fp-rhv2-5gv8,
  GHSA-xqr8-7jwr-rhp7.

urllib3 (22 advisories) is not drafted yet. More advisories are hand-checked
and promoted from `deferred/` once the pipeline works on these 10.

## Sign-off rule

**No pipeline code is judged against an unsigned file.** Every file carries
`"signed_off": false` until the owner has checked it and flips it to `true`.
The evaluator (`pipeline/evaluate.py`) reads only the top-level files of this
directory and refuses any whose `signed_off` is false.

| File | Signed off |
| --- | --- |
| GHSA-6757-jp84-gxfx (pyyaml, CVE-2020-1747) | no |
| GHSA-8q59-q68h-6hv4 (pyyaml, CVE-2020-14343) | no |
| GHSA-x84v-xcm2-53pg (requests, CVE-2018-18074) | no |
| GHSA-j8r2-6x86-q33q (requests, CVE-2023-32681) | no |
| GHSA-9hjg-9r4m-mvj7 (requests, CVE-2024-47081) | no |
| GHSA-q2x7-8rv6-6q7h (jinja2, CVE-2024-56326) | no |
| GHSA-h75v-3vvj-5mfj (jinja2, CVE-2024-34064) | no |
| GHSA-gmj6-6f8f-6699 (jinja2, CVE-2024-56201) | no |
| GHSA-cpwx-vrp4-4pq7 (jinja2, CVE-2025-27516) | no |
| GHSA-248v-346w-9cwc (certifi, CVE-2024-39689) | no |

The `signed_off` field in each file is the one the evaluator reads; this
table mirrors it for people.

## File format

Same shape as a pipeline record, restricted to the judged fields:

| Field | Meaning |
| --- | --- |
| `id`, `aliases`, `package`, `ecosystem` | From OSV. `id` is the GHSA ID. |
| `status` | `found`, `unknown` or `not_code`. |
| `fix_commits` | Full SHAs of the commits that fix the vulnerability. Informational; the evaluator does not score them. |
| `rejected_commits` | Commits the advisory links (or that sit in the release range) that are **not** the fix, each with the reason. These are the known traps. |
| `vulnerable` | The vulnerable code, as `{"name", "kind"}`. Scored for recall and precision by name. |
| `entry_points` | Public names a project can call that reach the vulnerable code. Scored for recall by name. |
| `truth_evidence` | Sentences with links justifying every entry above. |
| `notes` | Judgment calls and anything the owner should look at twice. |
| `signed_off` | See above. |

## How the answers were decided

These rules were applied the same way to every advisory, including the
deferred ones. Where a rule produces a debatable answer, the file says so in
`notes`.

**Vulnerable code.** A function or method is listed when the fix commit
changes its body in a way that is not cosmetic, named by its fully qualified
pre-fix name (`yaml.constructor.FullConstructor.set_python_instance_state`).

- Deleted functions are listed (they are the code the vulnerable versions ran).
- Functions the fix adds are not listed; they are named in the evidence.
- Docstring, comment and formatting changes do not count.
- `module_level` is listed only when the changed module-level statements are
  executable logic or data the vulnerability depends on: PyYAML's constructor
  registrations, Jinja's `_attr_key_re` regex. Changed imports and new helper
  definitions do not count.
- Where the fix is committed once per code copy (PyYAML `lib/` and `lib3/`)
  or once per branch, the function is named once.
- Code the fix leaves unchanged is not listed even when it holds the flawed
  logic. Those cases are flagged in `notes`.

**Entry points.** Public names (no leading underscore anywhere in the path)
whose call graph inside the package reaches a vulnerable function, written by
their shortest public import path: `yaml.full_load` rather than
`yaml.__init__.full_load`, `requests.get` rather than `requests.api.get`,
`requests.Session.send` for a method. A vulnerable function that is itself
public is also an entry point.

- Names whose use is unsafe by design are not listed for advisories about
  the safer alternative: `yaml.Loader`, `yaml.UnsafeLoader`, `yaml.unsafe_load`
  are not entry points for the FullLoader advisories.
- Only recall is measured on entry points, so a pipeline that reports more
  entry points than the truth file is not penalised. The truth lists the ones
  that must not be missed.
- Jinja template filters (`xmlattr`, `attr`) are never called by name inside
  Jinja: `jinja2.filters.FILTERS` holds them, every `Environment` copies that
  table into `self.filters`, and compiled template code or
  `Environment.call_filter` looks them up by string. Their truth files list
  the filter function plus the public names that render templates or call
  filters. This follows the same rule that lists the `Environment` compile
  API for GHSA-gmj6-6f8f-6699, where `visit_FromImport` is reached by
  dynamic dispatch and only for templates containing `{% from %}`. For the
  `attr` advisory only the sandbox classes and `call_filter` are listed, since
  the filter is harmless without a sandbox (the unsafe-by-design rule above).
  A call-graph walker cannot derive these entry points, because the only
  reference to the filter function is the dict literal, so they come
  from `data/overrides.json`, drafted by the pipeline builder and signed off
  per entry by the owner. What stays unseeable is whether a given
  template uses the filter: a match on these entry points means "reachable,
  template content not checked", and the scan side must not turn silence
  about template content into "not found".

**Status.** `not_code` for certifi (a distrusted root certificate in
`cacert.pem`); the fix commit also bumps `__version__` in
`certifi/__init__.py`, which must not be mistaken for vulnerable code.
No advisory in the phase A set is `unknown`.

## Traps in the phase A set

Cases a naive pipeline gets wrong, each recorded in the file's
`rejected_commits` or `notes`:

- **Linked commit introduced the vulnerable feature** (GHSA-6757-jp84-gxfx
  links the 5.1 commit that added FullLoader; it is inside the affected range).
- **Fix split across code copies** (PyYAML `lib/` and `lib3/`; the Python 2
  copy does not parse with `ast`, the `lib3/` copy carries the same change).
- **Fix is module-level only** (GHSA-8q59-q68h-6hv4; no function body changes).
- **Two-parent commit with an empty `git show`** (GHSA-gmj6-6f8f-6699): diff
  against the first parent.
- **Deleted functions** (GHSA-q2x7-8rv6-6q7h): they are vulnerable code, not
  nothing.
- **Cosmetic change inside the fix commit** (docstring edits in
  GHSA-h75v-3vvj-5mfj and GHSA-cpwx-vrp4-4pq7).
- **A `.py` change that is only a version string** (GHSA-248v-346w-9cwc).
- **Vulnerable function referenced only from a data table**
  (GHSA-h75v-3vvj-5mfj, GHSA-cpwx-vrp4-4pq7): no call-graph edge leads to
  `do_xmlattr` or `do_attr`; the entry points come from the overrides file.

The deferred files add: a version-bump-only link, a reverted commit that is
still an ancestor of the fixed tag, an incomplete prior fix linked as the fix
with a wrong OSV range, and unrelated refactors inside the release range.
