# TODO

## Known issues

### Findings don't say whether a package is direct or transitive

A `direct` field (true/false) was removed in v0.1 because it was wrong for lock files.

**What went wrong:** depscan marked a package as direct when osv-scanner
reported it from the dependency file itself (source type `lockfile`), and
as transitive when it came only from osv-scanner's resolved dependency tree.
That works for `requirements.txt`, where only the listed packages come from
the file. But real lock files (`package-lock.json`, `poetry.lock`, ...) list
every package, including transitive ones, so everything was labeled direct.
Example: in an npm project, `qs` (a dependency of `express`) showed as direct.

**Why it can't be fixed from osv-scanner's output:** osv-scanner's JSON doesn't
say which packages are direct.

**How to fix it:** read the direct dependencies from each ecosystem's own files:

- npm: the root entry (`packages[""].dependencies` / `devDependencies`) in `package-lock.json`
- Poetry: `[tool.poetry.dependencies]` or `[project].dependencies` in `pyproject.toml`
- requirements.txt: the source-type check above already works

Add the field back only once it's reliable for every supported file type,
or leave it out for file types it can't be worked out for. Don't fill it with a guess.
