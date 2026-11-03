"""Which functions a fix commit changed, found by parsing the code around the diff.

Git's hunk headers name the wrong function too often, so each changed line is
mapped to the innermost function, method or class that contains it in the
parsed source. Names are fully qualified from the module
(`yaml.constructor.FullConstructor.set_python_instance_state`).

Rules (design: Part 1, step 6):
- modified function: included; added function: excluded but listed;
  deleted function: included;
- docstring, comment and formatting changes only: excluded (the parsed body
  is compared with docstrings stripped);
- changes outside any function: class_level or module_level, reported only
  when an existing statement changed or disappeared, never for additions.
  Imports and docstrings are ignored at those levels.
"""

import ast
import copy
from collections import Counter

_DEF_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_IGNORED_AT_LEVEL = _DEF_TYPES + (ast.Import, ast.ImportFrom)
# Assignments to these names are release bookkeeping, never vulnerable code.
_VERSION_NAMES = {"__version__", "__version_info__", "version_info", "version", "VERSION",
                  "__release__", "release"}


def changed_functions(before, after, before_lines, after_lines, module):
    """Map changed lines to definitions and classify each as modified/deleted/added.

    Returns {"vulnerable": [{"name", "kind", "change", "evidence"}],
             "added": [names], "cosmetic": [names], "notes": [str]}.
    """
    result = {"vulnerable": [], "added": [], "cosmetic": [], "notes": []}
    try:
        before_tree = ast.parse(before) if before.strip() else ast.Module(body=[], type_ignores=[])
    except SyntaxError as exc:
        result["notes"].append(
            f"{module}: source before the fix does not parse (line {exc.lineno}: {exc.msg}); skipped")
        return result
    try:
        after_tree = ast.parse(after) if after.strip() else ast.Module(body=[], type_ignores=[])
    except SyntaxError as exc:
        result["notes"].append(
            f"{module}: source after the fix does not parse (line {exc.lineno}: {exc.msg}); skipped")
        return result

    before_defs = _definitions(before_tree)
    after_defs = _definitions(after_tree)

    touched = {}          # qualname -> {"before": set, "after": set} for functions/methods
    classes = set()       # classes with changed lines outside their methods
    module_touched = False
    added = []

    for line in before_lines:
        name = _innermost(before_defs, line)
        if name is None:
            module_touched = True
        elif before_defs[name]["kind"] == "class":
            classes.add(name)
        else:
            touched.setdefault(name, {"before": set(), "after": set()})["before"].add(line)

    for line in after_lines:
        name = _innermost(after_defs, line)
        if name is None:
            module_touched = True
            continue
        new_name = _outermost_new(name, before_defs)
        if new_name is not None:
            if new_name not in added:
                added.append(new_name)
        elif after_defs[name]["kind"] == "class":
            classes.add(name)
        else:
            touched.setdefault(name, {"before": set(), "after": set()})["after"].add(line)

    for name in sorted(touched, key=lambda n: before_defs[n]["start"] if n in before_defs else 0):
        lines = touched[name]
        if name not in before_defs:
            continue  # only reachable through after-lines of a new def, handled above
        info = before_defs[name]
        fqn = f"{module}.{name}"
        if name not in after_defs:
            result["vulnerable"].append({
                "name": fqn, "kind": info["kind"], "change": "deleted",
                "evidence": [f"deleted by the fix (lines {_fmt(lines['before'])} before)"],
            })
        elif _normalized(info["node"]) == _normalized(after_defs[name]["node"]):
            result["cosmetic"].append(fqn)
        else:
            result["vulnerable"].append({
                "name": fqn, "kind": info["kind"], "change": "modified",
                "evidence": [
                    f"modified by the fix (lines {_fmt(lines['before'])} before, "
                    f"{_fmt(lines['after'])} after)",
                    "body changed, not only docstrings or formatting",
                ],
            })

    for name in sorted(classes):
        if name in before_defs and name in after_defs:
            gone = _level_statements(before_defs[name]["node"]) - _level_statements(after_defs[name]["node"])
            if gone:
                result["vulnerable"].append({
                    "name": f"{module}.{name}", "kind": "class_level", "change": "modified",
                    "evidence": [f"class-level statement changed or removed: {_describe(gone)}"],
                })

    if module_touched:
        gone = _level_statements(before_tree) - _level_statements(after_tree)
        if gone:
            result["vulnerable"].append({
                "name": module, "kind": "module_level", "change": "modified",
                "evidence": [f"module-level statement changed or removed: {_describe(gone)}"],
            })

    result["added"] = [f"{module}.{name}" for name in added]
    return result


def _definitions(tree):
    """{qualname: {"node", "kind", "start", "end"}} for every def and class."""
    defs = {}

    def walk(node, prefix, in_class):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _DEF_TYPES):
                name = prefix + child.name
                if isinstance(child, ast.ClassDef):
                    kind = "class"
                else:
                    kind = "method" if in_class else "function"
                start = min([child.lineno] + [d.lineno for d in child.decorator_list])
                defs[name] = {"node": child, "kind": kind, "start": start, "end": child.end_lineno}
                walk(child, name + ".", isinstance(child, ast.ClassDef))
            else:
                walk(child, prefix, in_class)

    walk(tree, "", False)
    return defs


def _innermost(defs, line):
    best = None
    for name, info in defs.items():
        if info["start"] <= line <= info["end"]:
            if best is None or (info["end"] - info["start"]) < (defs[best]["end"] - defs[best]["start"]):
                best = name
    return best


def _outermost_new(name, before_defs):
    """The shortest prefix of a dotted name that does not exist before the fix, or None."""
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        prefix = ".".join(parts[:i])
        if prefix not in before_defs:
            return prefix
    return None


def _normalized(node):
    """ast.dump of a definition with docstrings removed (no line numbers)."""
    node = copy.deepcopy(node)
    for sub in ast.walk(node):
        body = getattr(sub, "body", None)
        if isinstance(body, list) and body and _is_docstring(body[0]):
            del body[0]
    return ast.dump(node)


def _is_docstring(stmt):
    return (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str))


def _level_statements(node):
    """Statements directly in a module or class body, minus defs, imports,
    docstrings and version-string assignments."""
    return Counter(
        _normalized(stmt) for stmt in node.body
        if not isinstance(stmt, _IGNORED_AT_LEVEL)
        and not _is_docstring(stmt)
        and not _is_version_assignment(stmt)
    )


def _is_version_assignment(stmt):
    if isinstance(stmt, ast.Assign):
        targets = stmt.targets
    elif isinstance(stmt, ast.AnnAssign):
        targets = [stmt.target]
    else:
        return False
    return all(isinstance(t, ast.Name) and t.id in _VERSION_NAMES for t in targets)


def _describe(gone):
    """Short source text of the statements that disappeared, for evidence."""
    texts = []
    for dump in gone:
        try:
            texts.append(ast.unparse(ast.parse(_from_dump(dump))).strip())
        except Exception:  # noqa: BLE001 - evidence only
            texts.append(dump[:80])
    return "; ".join(t[:100] for t in texts)


def _from_dump(dump):
    """Rebuild a statement from its ast.dump text (used only to print evidence)."""
    namespace = {name: getattr(ast, name) for name in dir(ast)}
    node = eval(dump, {"__builtins__": {}}, namespace)  # noqa: S307 - our own dump output
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])))


def _fmt(lines):
    return ", ".join(str(n) for n in sorted(lines)) if lines else "none"
