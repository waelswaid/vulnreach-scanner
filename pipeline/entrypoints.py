"""The call graph inside a package and the public names that reach a vulnerable item.

The walker is strict: an edge exists only for a call it can resolve to a
definition in the package (`high`), or for a method call on an object whose
class it cannot resolve, matched by method name alone (`medium`). A function
used as a value (a dict entry, an argument), a decorator, or a name built at
runtime makes no edge. Walking `callers` backwards from a vulnerable item
gives every definition that can lead to it; the public ones are its entry
points.
"""

import ast
from collections import deque
from pathlib import Path

from pipeline import commits
from pipeline.repos import git

_FUNC_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)
_DEF_TYPES = _FUNC_TYPES + (ast.ClassDef,)
_TOP_TYPES = _DEF_TYPES + (ast.Import, ast.ImportFrom, ast.Assign)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def sources_at(repo_dir, rev, package):
    """Every library file of the package (PyPI name) at `rev`, with its source."""
    return [
        {"module": module, "path": path, "source": git(repo_dir, "show", f"{rev}:{path}")}
        for path, module in commits.library_files_at(repo_dir, rev, package)
    ]


def sources_from_tree(root, package):
    """Every root/<package>/**/*.py file, with its module and root-relative path."""
    root = Path(root)
    sources = []
    for file in sorted((root / package).rglob("*.py")):
        path = file.relative_to(root).as_posix()
        sources.append({
            "module": commits.module_for_path(path, package),
            "path": path,
            "source": file.read_text(encoding="utf-8"),
        })
    return sources


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

class Graph:
    """Definitions, call edges and public names of one package."""

    def __init__(self):
        self.defs = {}        # FQN -> {"kind", "module", "file", "line"}
        self.callers = {}     # callee FQN -> [(caller FQN, "high" | "medium")]
        self.public = {}      # FQN -> shortest public import path
        self.references = {}  # filled by Task 3
        self.notes = []       # skipped files
        self.bases = {}       # class FQN -> base class FQNs in the package


def build_graph(sources, package):
    """Build the call graph of a package; `package` is its import name."""
    return _Builder(sources, package).graph


class _Builder:
    def __init__(self, sources, package):
        self.package = package
        self.graph = Graph()
        self.trees = {}       # module -> (ast.Module, path, is_init)
        self.tables = {}      # module -> {name: binding}
        self.stars = {}       # __init__ module -> {name: binding} from `import *`
        self.all_names = {}   # module -> __all__ list of strings
        self.bodies = []      # (FQN, def node, enclosing class FQN or None, module)
        self._parse(sources)
        for module, (tree, path, _) in self.trees.items():
            self._collect(module, tree, path)
        for module in self.trees:
            self._collect_stars(module)
        for module, (tree, _, _) in self.trees.items():
            self._collect_bases(module, tree)
        self._collect_edges()
        self._collect_public()

    # -- pass 1: modules, definitions, name tables --------------------------

    def _parse(self, sources):
        for source in sources:
            module, path = source["module"], source["path"]
            if module in self.trees:
                self.graph.notes.append(f"{path}: duplicate module {module}, skipped")
                continue
            try:
                tree = ast.parse(source["source"])
            except (SyntaxError, ValueError) as error:
                line = getattr(error, "lineno", None) or 0
                message = getattr(error, "msg", None) or str(error)
                self.graph.notes.append(f"{path}: does not parse (line {line}: {message}), skipped")
                continue
            is_init = path == "__init__.py" or path.endswith("/__init__.py")
            self.trees[module] = (tree, path, is_init)

    def _collect(self, module, tree, path):
        table = self.tables[module] = {}
        for node in _top_level(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        table[alias.asname] = self._module_binding(alias.name)
                    else:
                        top = alias.name.split(".")[0]
                        table[top] = self._module_binding(top)
            elif isinstance(node, ast.ImportFrom):
                target = self._import_target(module, node)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    name = alias.asname or alias.name
                    if target is None:
                        table[name] = None
                    elif f"{target}.{alias.name}" in self.trees:
                        table[name] = ("module", f"{target}.{alias.name}")
                    else:
                        table[name] = ("from", target, alias.name)
            elif isinstance(node, ast.Assign):
                names = _string_list(node)
                if names is not None:
                    self.all_names[module] = names
            else:
                fqn = f"{module}.{node.name}"
                kind = "class" if isinstance(node, ast.ClassDef) else "function"
                self._add_def(fqn, kind, module, path, node)
                table[node.name] = ("def", fqn)
                if kind == "function":
                    self.bodies.append((fqn, node, None, module))
                else:
                    for child in _top_level(node):
                        if isinstance(child, _FUNC_TYPES):
                            method = f"{fqn}.{child.name}"
                            self._add_def(method, "method", module, path, child)
                            self.bodies.append((method, child, fqn, module))

    def _add_def(self, fqn, kind, module, path, node):
        self.graph.defs[fqn] = {"kind": kind, "module": module, "file": path, "line": node.lineno}

    def _in_package(self, dotted):
        return dotted == self.package or dotted.startswith(self.package + ".")

    def _module_binding(self, dotted):
        return ("module", dotted) if self._in_package(dotted) else None

    def _import_target(self, module, node):
        """The package module an ImportFrom reads from, or None outside the package."""
        if node.level:
            is_init = self.trees[module][2]
            parts = module.split(".") if is_init else module.split(".")[:-1]
            if node.level - 1 > len(parts) - 1:
                return None
            parts = parts[: len(parts) - (node.level - 1)]
            if node.module:
                parts += node.module.split(".")
            target = ".".join(parts)
        else:
            target = node.module
        return target if self._in_package(target) else None

    def _collect_bases(self, module, tree):
        for node in _top_level(tree):
            if isinstance(node, ast.ClassDef):
                bases = []
                for base in node.bases:
                    resolved = self._resolve_expr(base, module)
                    if resolved and resolved[0] == "def" and self._kind(resolved[1]) == "class":
                        bases.append(resolved[1])
                self.graph.bases[f"{module}.{node.name}"] = bases

    def _collect_stars(self, module):
        """Names a module gets from `from .mod import *`."""
        stars = self.stars[module] = {}
        tree = self.trees[module][0]
        for node in _top_level(tree):
            if not isinstance(node, ast.ImportFrom) or node.names[0].name != "*":
                continue
            target = self._import_target(module, node)
            if target not in self.trees:
                continue
            if target in self.all_names:
                for name in self.all_names[target]:
                    stars[name] = ("from", target, name)
            else:
                for fqn, info in self.graph.defs.items():
                    name = fqn[len(target) + 1:]
                    if (info["module"] == target and info["kind"] != "method"
                            and not name.startswith("_")):
                        stars[name] = ("def", fqn)

    # -- name resolution -----------------------------------------------------

    def _kind(self, fqn):
        info = self.graph.defs.get(fqn)
        return info["kind"] if info else None

    def _lookup(self, module, name, seen):
        """Resolve a name bound in a module: ("module", m), ("def", fqn) or None."""
        binding = self.tables.get(module, {}).get(name)
        if binding is None:
            binding = self.stars.get(module, {}).get(name)
        return self._resolve_binding(binding, seen)

    def _resolve_binding(self, binding, seen=None):
        if binding is None or binding[0] in ("module", "def"):
            return binding
        _, target, name = binding
        seen = set() if seen is None else seen
        if (target, name) in seen:
            return None
        seen.add((target, name))
        return self._member(target, name, seen)

    def _member(self, module, name, seen=None):
        """What `module.name` is in the package."""
        if f"{module}.{name}" in self.trees:
            return ("module", f"{module}.{name}")
        resolved = self._lookup(module, name, set() if seen is None else seen)
        if resolved is None and self._kind(f"{module}.{name}") in ("function", "class"):
            resolved = ("def", f"{module}.{name}")
        return resolved

    def _resolve_expr(self, node, module):
        """Resolve a Name or Attribute chain to a package module or definition."""
        if isinstance(node, ast.Name):
            return self._lookup(module, node.id, set())
        if isinstance(node, ast.Attribute):
            base = self._resolve_expr(node.value, module)
            if base is None:
                return None
            if base[0] == "module":
                return self._member(base[1], node.attr)
            if self._kind(base[1]) == "class":
                method = self._method(base[1], node.attr)
                return ("def", method) if method else None
        return None

    def _method(self, cls, name, include_self=True, seen=None):
        """The first definition of method `name` in cls or its bases, depth-first."""
        seen = set() if seen is None else seen
        if cls in seen:
            return None
        seen.add(cls)
        if include_self and self._kind(f"{cls}.{name}") == "method":
            return f"{cls}.{name}"
        for base in self.graph.bases.get(cls, []):
            found = self._method(base, name, True, seen)
            if found:
                return found
        return None

    def _constructor(self, cls):
        return self._method(cls, "__init__") or cls

    # -- pass 2: edges ---------------------------------------------------------

    def _collect_edges(self):
        methods_by_name = {}
        for fqn, info in self.graph.defs.items():
            if info["kind"] == "method":
                methods_by_name.setdefault(fqn.rsplit(".", 1)[1], []).append(fqn)
        edges = {}
        for caller, node, cls, module in self.bodies:
            local = _local_names(node)
            for call in _calls(node.body):
                for callee, confidence in self._targets(call, cls, module, local, methods_by_name):
                    key = (callee, caller)
                    if edges.get(key) != "high":
                        edges[key] = confidence
        for (callee, caller), confidence in sorted(edges.items()):
            self.graph.callers.setdefault(callee, []).append((caller, confidence))

    def _targets(self, call, cls, module, local, methods_by_name):
        """Callees of one call. A name bound inside the definition (a parameter,
        an assignment) is a value, never the module-level name it shadows."""
        func = call.func
        if isinstance(func, ast.Name):
            if func.id in local:
                return []
            return self._high(self._resolve_expr(func, module))
        if not isinstance(func, ast.Attribute):
            return []
        value = func.value
        if cls and isinstance(value, ast.Name) and value.id in ("self", "cls"):
            method = self._method(cls, func.attr)
            if method:
                return [(method, "high")]
        elif cls and _is_super_call(value):
            method = self._method(cls, func.attr, include_self=False)
            if method:
                return [(method, "high")]
        elif _root_name(value) not in local:
            resolved = self._resolve_expr(func, module)
            if resolved:
                return self._high(resolved)
            receiver = self._resolve_expr(value, module)
            if receiver and receiver[0] == "module":
                return []
        return [(method, "medium") for method in methods_by_name.get(func.attr, [])]

    def _high(self, resolved):
        if resolved is None or resolved[0] != "def":
            return []
        kind = self._kind(resolved[1])
        if kind == "class":
            return [(self._constructor(resolved[1]), "high")]
        return [(resolved[1], "high")]

    # -- public names ------------------------------------------------------------

    def _collect_public(self):
        module_paths = {module: {module} for module in self.trees}
        def_paths = {}
        for module, (_, _, is_init) in self.trees.items():
            if not is_init:
                continue
            names = list(self.tables[module]) + list(self.stars[module])
            for name in names:
                resolved = self._lookup(module, name, set())
                if resolved is None:
                    continue
                paths = module_paths if resolved[0] == "module" else def_paths
                paths.setdefault(resolved[1], set()).add(f"{module}.{name}")
        for fqn, info in self.graph.defs.items():
            if info["kind"] == "method":
                continue
            name = fqn[len(info["module"]) + 1:]
            candidates = {f"{path}.{name}" for path in module_paths.get(info["module"], ())}
            candidates |= def_paths.get(fqn, set())
            best = _shortest(p for p in candidates if _is_public(p))
            if best:
                self.graph.public[fqn] = best
        for fqn, info in self.graph.defs.items():
            if info["kind"] != "method":
                continue
            cls, name = fqn.rsplit(".", 1)
            if cls not in self.graph.public:
                continue
            if _is_dunder(name):
                self.graph.public[fqn] = self.graph.public[cls]
            elif not name.startswith("_"):
                self.graph.public[fqn] = f"{self.graph.public[cls]}.{name}"


def _top_level(node):
    """Definitions, imports and assignments directly in a module or class body,
    looking through if/try/with/for/while blocks but not into definitions."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _TOP_TYPES):
            yield child
        elif isinstance(child, ast.stmt) or isinstance(child, ast.excepthandler):
            yield from _top_level(child)


def _string_list(node):
    """The strings of `__all__ = [...]`, or None for any other assignment."""
    if (len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "__all__" and isinstance(node.value, ast.List)
            and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.value.elts)):
        return [e.value for e in node.value.elts]
    return None


def _calls(body):
    """Every ast.Call in a definition body, skipping decorators of nested definitions."""
    stack = list(reversed(body))
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Call):
            yield node
        children = list(ast.iter_child_nodes(node))
        if isinstance(node, _DEF_TYPES):
            children = [c for c in children if c not in node.decorator_list]
        stack.extend(reversed(children))


def _local_names(node):
    """Names bound inside a definition or its nested scopes: parameters,
    assignment, for, with, except, walrus and comprehension targets, nested
    definitions and imports. Names declared `global` stay module-level."""
    bound, declared_global = set(), set()
    for child in ast.walk(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = child.args
            for arg in args.posonlyargs + args.args + args.kwonlyargs + [args.vararg, args.kwarg]:
                if arg is not None:
                    bound.add(arg.arg)
            if child is not node and not isinstance(child, ast.Lambda):
                bound.add(child.name)
        elif isinstance(child, ast.ClassDef):
            bound.add(child.name)
        elif isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            bound.add(child.id)
        elif isinstance(child, ast.ExceptHandler) and child.name:
            bound.add(child.name)
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            for alias in child.names:
                if alias.name != "*":
                    bound.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(child, ast.Global):
            declared_global.update(child.names)
    return bound - declared_global


def _root_name(node):
    """The Name at the start of an attribute chain (`a` in `a.b.c`), or None."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _is_super_call(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "super")


def _is_dunder(part):
    return len(part) > 4 and part.startswith("__") and part.endswith("__")


def _is_public(path):
    return not any(part.startswith("_") for part in path.split("."))


def _shortest(paths):
    paths = list(paths)
    if not paths:
        return None
    return min(paths, key=lambda p: (p.count("."), len(p), p))


# ---------------------------------------------------------------------------
# Walk
# ---------------------------------------------------------------------------

def walk(sources, package, vulnerable):
    """Entry points of the vulnerable items: every public definition whose call
    chains reach an item, with the shortest chain as evidence."""
    graph = build_graph(sources, package)
    entries = {}
    for item in vulnerable:
        target = item["name"]
        any_next = _backward(graph, target, ("high", "medium"))
        high_next = _backward(graph, target, ("high",))
        for fqn in any_next:
            if fqn not in graph.public:
                continue
            high = fqn in high_next
            entry = {
                "name": graph.public[fqn],
                "defined_as": fqn,
                "confidence": "high" if high else "medium",
                "path": _chain(fqn, high_next if high else any_next),
            }
            current = entries.get(entry["name"])
            if current is None or _better(entry, current):
                entries[entry["name"]] = entry
    return {
        "entry_points": [entries[name] for name in sorted(entries)],
        "reasons": [],
        "notes": list(graph.notes),
    }


def _backward(graph, target, confidences):
    """Breadth-first over callers: {definition: next step towards target}."""
    next_step = {target: None}
    queue = deque([target])
    while queue:
        callee = queue.popleft()
        for caller, confidence in graph.callers.get(callee, []):
            if confidence in confidences and caller not in next_step:
                next_step[caller] = callee
                queue.append(caller)
    return next_step


def _chain(start, next_step):
    chain = [start]
    while next_step[chain[-1]] is not None:
        chain.append(next_step[chain[-1]])
    return chain


def _better(new, old):
    if new["confidence"] != old["confidence"]:
        return new["confidence"] == "high"
    return len(new["path"]) < len(old["path"])
