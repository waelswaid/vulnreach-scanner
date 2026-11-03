"""Check that the vulnerable names still exist across the affected versions.

Names come from the code just before the fix, but a project may pin a much
older affected release where a function lived elsewhere or had another name.
For the newest tag of each affected major.minor series, every name is looked
up in that release's package source. The result is the list of version
ranges where all names were confirmed (`names_verified_for`); at scan time an
installed version outside them gets "unknown", never "not found".
"""

import ast

import depscan
from pipeline import commits
from pipeline.repos import git, tag_for_version

_DEF_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def collect_names(source, module):
    """Fully qualified names of every function, method and class in the source."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    names = set()

    def walk(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _DEF_TYPES):
                qualname = prefix + child.name
                names.add(f"{module}.{qualname}")
                walk(child, qualname + ".")
            else:
                walk(child, prefix)

    walk(tree, "")
    return names


def series_of(version):
    """(major, minor) of a version string: '5.3.1' -> (5, 3), '5.4b1' -> (5, 4), '3' -> (3, 0)."""
    release = depscan.version_key(version)[0]
    major = release[0] if release else 0
    minor = release[1] if len(release) > 1 else 0
    return (major, minor)


def _next_series(label):
    major, minor = label.split(".")
    return f"{major}.{int(minor) + 1}"


def ranges_from_series(series):
    """Turn [(label, verified)] into restricted specifiers like '>=5.1, <5.4'.

    `verified` is True, False (names missing) or None (no tag matched). Each
    maximal run of True becomes one range; its upper bound is the series
    after the last verified one.
    """
    ranges = []
    start = last = None
    for label, verified in series:
        if verified is True:
            if start is None:
                start = label
            last = label
        elif start is not None:
            ranges.append(f">={start}, <{_next_series(last)}")
            start = last = None
    if start is not None:
        ranges.append(f">={start}, <{_next_series(last)}")
    return ranges


def verify_names(repo_dir, package, names, affected_versions):
    """Version ranges (per affected major.minor series) in which every name exists."""
    by_series = {}
    for version in affected_versions:
        by_series.setdefault(series_of(version), []).append(version)

    series = []
    for key in sorted(by_series):
        label = f"{key[0]}.{key[1]}"
        tag = None
        for version in sorted(by_series[key], key=depscan.version_key, reverse=True):
            tag = tag_for_version(repo_dir, package, version)
            if tag:
                break
        if tag is None:
            series.append((label, None))
            continue
        defined = names_at(repo_dir, tag, package)
        series.append((label, all(name in defined for name in names)))
    return ranges_from_series(series)


def names_at(repo_dir, rev, package):
    """Every module, function, method and class name in the package at `rev`."""
    defined = set()
    for path, module in commits.library_files_at(repo_dir, rev, package):
        defined.add(module)
        defined |= collect_names(git(repo_dir, "show", f"{rev}:{path}"), module)
    return defined
