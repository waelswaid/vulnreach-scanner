# Hand-checked truth set

One JSON file per advisory, holding the correct answer the reachability
pipeline is measured against (design: `2026-11-03-reachability-design.md`,
"The hand-checked set and measuring accuracy"). Each answer was drafted by
reading the advisory, the upstream repository and the fix commit, and is
signed off by the project owner before any pipeline code is judged against it.

## Scope

All 28 current OSV advisories for five of the six research packages:

| Package | Advisories |
| --- | --- |
| pyyaml | 4 |
| requests | 8 |
| jinja2 | 10 |
| idna | 2 |
| certifi | 4 |

urllib3 (22 advisories) is deferred to a later addition. Until it is added,
the design's urllib3 tricky cases (the unrelated old refactor, the 1.24.2
release commit that bundles several fixes) are not in the set.

## Sign-off rule

**No pipeline code is judged against an unsigned file.** Every file carries
`"signed_off": false` until the owner has checked it and flips it to `true`.
The evaluator (`pipeline/evaluate.py`) refuses any truth file whose
`signed_off` is false.

| File | Signed off |
| --- | --- |
| GHSA-rprw-h62v-c2w7 (pyyaml, CVE-2017-18342) | no |
| GHSA-3pqx-4fqf-j49f (pyyaml, CVE-2019-20477) | no |
| GHSA-6757-jp84-gxfx (pyyaml, CVE-2020-1747) | no |
| GHSA-8q59-q68h-6hv4 (pyyaml, CVE-2020-14343) | no |
| GHSA-cfj3-7x9c-4p3h (requests, CVE-2014-1829) | no |
| GHSA-652x-xj99-gmcc (requests, CVE-2014-1830) | no |
| GHSA-pg2w-x9wp-vw92 (requests, CVE-2015-2296) | no |
| GHSA-x84v-xcm2-53pg (requests, CVE-2018-18074) | no |
| GHSA-j8r2-6x86-q33q (requests, CVE-2023-32681) | no |
| GHSA-9wx4-h78v-vm56 (requests, CVE-2024-35195) | no |
| GHSA-9hjg-9r4m-mvj7 (requests, CVE-2024-47081) | no |
| GHSA-gc5v-m9x4-r6x2 (requests, CVE-2026-25645) | no |
| GHSA-8r7q-cvjq-x353 (jinja2, CVE-2014-1402) | no |
| GHSA-fqh9-2qgg-h84h (jinja2, CVE-2014-0012) | no |
| GHSA-hj2j-77xm-mc5v (jinja2, CVE-2016-10745) | no |
| GHSA-462w-v97r-4m45 (jinja2, CVE-2019-10906) | no |
| GHSA-g3rq-g295-4j3m (jinja2, CVE-2020-28493) | no |
| GHSA-h5c8-rqwp-cp95 (jinja2, CVE-2024-22195) | no |
| GHSA-h75v-3vvj-5mfj (jinja2, CVE-2024-34064) | no |
| GHSA-gmj6-6f8f-6699 (jinja2, CVE-2024-56201) | no |
| GHSA-q2x7-8rv6-6q7h (jinja2, CVE-2024-56326) | no |
| GHSA-cpwx-vrp4-4pq7 (jinja2, CVE-2025-27516) | no |
| GHSA-jjg7-2v4v-x38h (idna, CVE-2024-3651) | no |
| GHSA-65pc-fj4g-8rjx (idna, CVE-2026-45409) | no |
| GHSA-43fp-rhv2-5gv8 (certifi, CVE-2022-23491) | no |
| GHSA-xqr8-7jwr-rhp7 (certifi, CVE-2023-37920) | no |
| GHSA-248v-346w-9cwc (certifi, CVE-2024-39689) | no |
| GHSA-6q48-6c7w-9gw2 (certifi, no CVE) | no |

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

These rules were applied the same way to every advisory. Where a rule
produces a debatable answer, the file says so in `notes`.

**Vulnerable code.** A function or method is listed when the fix commit
changes its body in a way that is not cosmetic, named by its fully qualified
pre-fix name (`yaml.constructor.FullConstructor.set_python_instance_state`).

- Deleted functions are listed (they are the code the vulnerable versions ran).
- Functions the fix adds are not listed; they are named in the evidence.
- Docstring, comment and formatting changes do not count
  (PyYAML's `safe_load` in the 5.1 commit).
- `module_level` is listed only when the changed module-level statements are
  executable logic or data the vulnerability depends on: PyYAML's constructor
  registrations, Jinja's `_punctuation_re` and `_attr_key_re` regexes. Changed
  imports and new helper definitions do not count.
- Where the fix is committed once per code copy (PyYAML `lib/` and `lib3/`)
  or once per branch, the function is named once.
- Code the fix leaves unchanged is not listed even when it holds the flawed
  logic (requests' `HTTPAdapter.get_connection`, PyYAML's
  `construct_python_object_apply`). Those cases are flagged in `notes`.

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
- Jinja template filters (`urlize`, `xmlattr`, `attr`) are reached from
  templates through the filter table, not through a Python call. Their truth
  files list the filter function as the entry point and say in the evidence
  that Python call analysis cannot see template usage. This is a known gap for
  the scan side, not something the pipeline can fix.

**Status.** `not_code` for the four certifi advisories (distrusted root
certificates in `cacert.pem`); the fix commits also bump `__version__` in
`certifi/__init__.py`, which must not be mistaken for vulnerable code.
No advisory in this set is `unknown`: every one has a findable fix commit,
including the five with no commit link in OSV.

## Traps in this set

Cases a naive pipeline gets wrong, each recorded in the file's
`rejected_commits` or `notes`:

- **Linked commit is the version bump** (idna GHSA-jjg7-2v4v-x38h): the real
  fix is a separate commit in the same release.
- **Linked commit introduced the vulnerable feature** (PyYAML
  GHSA-6757-jp84-gxfx links the 5.1 commit that added FullLoader).
- **Linked commit was reverted before release** (PyYAML
  GHSA-rprw-h62v-c2w7 links the retracted 4.1 change; it is an ancestor of
  tag 5.1 but its code is not).
- **Linked commit is the previous, incomplete fix, and OSV's fixed version is
  wrong** (Jinja GHSA-fqh9-2qgg-h84h: OSV says fixed in 2.7.2, the fix is in
  2.7.3). A release check driven by OSV's range rejects the real fix. This one
  needs an override.
- **Two-parent commit with an empty `git show`** (Jinja GHSA-gmj6-6f8f-6699):
  diff against the first parent.
- **Fix split across code copies** (PyYAML `lib/` and `lib3/`, two commits for
  GHSA-rprw-h62v-c2w7).
- **Fix is module-level only** (PyYAML GHSA-3pqx-4fqf-j49f and
  GHSA-8q59-q68h-6hv4; no function body changes).
- **Unrelated refactors in the release range** (idna 068f48f, 9d86ba6,
  ab7d46c, c18b804; requests 97cf16e9 moves the CVE-2014-1829 fix into a new
  method). Relevant to phase B's commit ranking.
- **Cosmetic change inside the fix commit** (PyYAML `safe_load`,
  Jinja `SandboxedEnvironment` docstring, `FileSystemBytecodeCache` docstring).
- **Python 2 source in the diff** (PyYAML `lib/`): the `ast` module cannot
  parse it; the `lib3/` copy carries the same change.
