# depscan

Flags vulnerable dependencies in your projects with a clean, readable report
and a JSON file that other tools can build on.

depscan uses [osv-scanner](https://github.com/google/osv-scanner) to find
known vulnerabilities in your dependencies, then groups duplicate advisories,
ranks findings by severity, and shows which version to upgrade to.

> **Status: v0.1.** This version only flags vulnerable packages. The long-term
> goal is *reachability analysis*: telling you which vulnerable functions your
> code actually calls, so you can separate real risk from noise.

## Requirements

- Python 3 (tested on 3.14). No Python packages needed, only the standard library.
- osv-scanner on your `PATH`:

  ```powershell
  winget install Google.OSVScanner                                     # Windows
  brew install osv-scanner                                             # macOS
  go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest   # with Go
  ```

  Or download a release from the
  [osv-scanner releases page](https://github.com/google/osv-scanner/releases).
  Open a new terminal after installing so it's on your `PATH`.

## Usage

```
python depscan.py <project-folder> [--output FILE] [--no-resolve]
```

| Option | What it does |
| --- | --- |
| `--output`, `-o` | Where to write the JSON report (default: `findings.json`) |
| `--no-resolve` | Only check packages listed in your dependency files, skipping their dependencies |

Example:

```
$ python depscan.py tests/fixtures/pyyaml_project

depscan report for tests/fixtures/pyyaml_project

pyyaml 5.3 (PyPI) - upgrade to 5.4
  found in requirements.txt
  [CRITICAL] GHSA-6757-jp84-gxfx / CVE-2020-1747  (fixed in 5.3.1)
             Improper Input Validation in PyYAML
  [CRITICAL] GHSA-8q59-q68h-6hv4 / CVE-2020-14343  (fixed in 5.4)
             Improper Input Validation in PyYAML

2 vulnerabilities in 1 package

JSON written to findings.json
```

Packages are sorted with the most severe issues first. The upgrade target is
the lowest version that fixes every listed vulnerability.

## Supported files

depscan scans whatever osv-scanner can read in the folder (searching
subfolders too). Tested so far:

- `requirements.txt`
- `poetry.lock`
- `package-lock.json`

osv-scanner also supports many others (for example `Pipfile.lock`, `uv.lock`,
`yarn.lock`, `pnpm-lock.yaml`, `go.mod`, `Cargo.lock`, `Gemfile.lock`), which
should work but haven't been tested with depscan yet.

## Dependencies of your dependencies

A `requirements.txt` usually lists only the packages you chose, not the
packages *they* depend on. By default, depscan has osv-scanner work out that
full dependency tree using live data from the package registry (PyPI, npm),
so a vulnerable package pulled in by one of yours still gets flagged.

These versions are what a fresh install would get today, not necessarily what
is installed on your machine, so results can change as new versions are
released. Use `--no-resolve` to check only what you listed. Lock files already
pin every package, so this doesn't apply to them.

## JSON output

```json
{
  "tool": "depscan",
  "tool_version": "0.1",
  "osv_scanner_version": "2.7.0",
  "scanned_at": "2026-11-02T23:30:27+00:00",
  "target": "C:\\path\\to\\project",
  "resolution": "native",
  "findings": [
    {
      "package": "pyyaml",
      "version": "5.3",
      "ecosystem": "PyPI",
      "vulnerability_id": "GHSA-6757-jp84-gxfx",
      "aliases": ["CVE-2020-1747", "PYSEC-2020-96"],
      "severity": "critical",
      "cvss_score": "9.8",
      "fixed_version": "5.3.1",
      "summary": "Improper Input Validation in PyYAML",
      "source_file": "requirements.txt"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `resolution` | `native` if dependencies of dependencies were checked, `none` with `--no-resolve` |
| `vulnerability_id` | The GitHub advisory ID when there is one, otherwise the first ID osv-scanner lists |
| `aliases` | Other IDs for the same issue (CVE, PYSEC, ...) |
| `severity` | `critical`, `high`, `moderate`, `low` or `unknown`, from the CVSS score, or the advisory's own rating when there is no score |
| `cvss_score` | The highest CVSS score osv-scanner found, or `null` |
| `fixed_version` | The lowest version that fixes this issue, or `null` if there is no fix |
| `source_file` | The dependency file the package came from, relative to the scanned folder |

Each finding is one vulnerability in one package. Advisories from different
databases that describe the same issue are merged into one finding.

## Testing

`tests/fixtures/pyyaml_project/` is a small fake project that pins an old,
vulnerable PyYAML. One file calls the vulnerable function (`yaml.full_load`)
and another only calls the safe one (`yaml.safe_load`), ready for the future
reachability check. See its [README](tests/fixtures/pyyaml_project/README.md)
for the expected results.

```
python depscan.py tests/fixtures/pyyaml_project
```

## Known limitations

- Findings don't say whether a package is a direct or transitive dependency
  yet. See [TODO.md](TODO.md).
- Picking the fix version uses a simple version comparison that handles
  normal version numbers but isn't a full version parser.
- The exit code is always 0 after a successful scan. Failing CI builds on
  critical findings is planned.

## Roadmap

1. **v0.1:** flag vulnerable packages *(done)*
2. **Reachability:** check whether your code calls the vulnerable functions,
   marking each finding as reachable, not found, or unknown
3. Library and CLI, CI exit codes, tests
4. Typosquatting and dependency confusion checks
