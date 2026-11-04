"""Unit tests for pipeline.entrypoints: call graph, public names, entry points.

Run from the repository root:
    python -m unittest tests.test_entrypoints
"""

import tempfile
import textwrap
import unittest
from pathlib import Path

from pipeline import entrypoints
from tests.test_repos import run_git


def make_pkg(root, files):
    """Write root/pkg/<rel> for every file and return sources_from_tree(root, "pkg")."""
    for rel, text in files.items():
        path = Path(root) / "pkg" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text), encoding="utf-8")
    return entrypoints.sources_from_tree(Path(root), "pkg")


def walk(files, *items):
    """Walk a fresh package for the given (name, kind) items."""
    with tempfile.TemporaryDirectory() as tmp:
        src = make_pkg(tmp, files)
    vulnerable = [{"name": name, "kind": kind} for name, kind in items]
    return entrypoints.walk(src, "pkg", vulnerable)


def graph_of(files):
    with tempfile.TemporaryDirectory() as tmp:
        src = make_pkg(tmp, files)
    return src, entrypoints.build_graph(src, "pkg")


def names(result):
    return [e["name"] for e in result["entry_points"]]


def by_name(result):
    return {e["name"]: e for e in result["entry_points"]}


class SourcesTest(unittest.TestCase):
    def test_sources_from_tree_gives_module_and_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = make_pkg(tmp, {"__init__.py": "", "sub/core.py": "X = 1\n"})
        self.assertEqual(src, [
            {"module": "pkg", "path": "pkg/__init__.py", "source": ""},
            {"module": "pkg.sub.core", "path": "pkg/sub/core.py", "source": "X = 1\n"},
        ])

    def test_sources_at_reads_library_files_at_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / "pkg").mkdir(parents=True)
            (repo / "pkg" / "__init__.py").write_text("", encoding="utf-8")
            (repo / "pkg" / "core.py").write_text("def run():\n    pass\n", encoding="utf-8")
            run_git(repo, "init", "-q")
            run_git(repo, "add", ".")
            run_git(repo, "commit", "-q", "-m", "one")
            src = entrypoints.sources_at(repo, "HEAD", "pkg")
        self.assertEqual(src, [
            {"module": "pkg", "path": "pkg/__init__.py", "source": ""},
            {"module": "pkg.core", "path": "pkg/core.py", "source": "def run():\n    pass\n"},
        ])


class WalkTest(unittest.TestCase):
    def test_public_caller_of_private_function_found(self):
        result = walk({
            "__init__.py": "",
            "core.py": """
                def _inner():
                    pass

                def run():
                    _inner()
            """,
        }, ("pkg.core._inner", "function"))
        self.assertEqual(names(result), ["pkg.core.run"])
        self.assertEqual(result["entry_points"][0]["path"], ["pkg.core.run", "pkg.core._inner"])
        self.assertEqual(result["entry_points"][0]["confidence"], "high")
        self.assertEqual(result["reasons"], [])
        self.assertEqual(result["notes"], [])

    def test_reexport_gives_shortest_public_path_with_defined_as(self):
        result = walk({
            "__init__.py": "from .core import run as run\n",
            "core.py": """
                def _inner():
                    pass

                def run():
                    _inner()
            """,
        }, ("pkg.core._inner", "function"))
        self.assertEqual(result["entry_points"], [{
            "name": "pkg.run", "defined_as": "pkg.core.run", "confidence": "high",
            "path": ["pkg.core.run", "pkg.core._inner"],
        }])

    def test_reexport_through_absolute_import_and_alias(self):
        result = walk({
            "__init__.py": "from pkg.core import run as start\n",
            "core.py": """
                def _inner():
                    pass

                def run():
                    _inner()
            """,
        }, ("pkg.core._inner", "function"))
        self.assertEqual(names(result), ["pkg.start"])

    def test_star_reexport_lists_public_names(self):
        result = walk({
            "__init__.py": "from .core import *\nfrom .loader import *\n",
            "core.py": """
                def _v():
                    pass

                def run():
                    _v()

                class Loader:
                    def load(self):
                        _v()
            """,
            "loader.py": """
                __all__ = ["load_all"]
                from .core import _v

                def load_all():
                    _v()

                def load_one():
                    _v()
            """,
        }, ("pkg.core._v", "function"))
        self.assertEqual(names(result),
                         ["pkg.Loader.load", "pkg.load_all", "pkg.loader.load_one", "pkg.run"])
        self.assertEqual(by_name(result)["pkg.Loader.load"]["defined_as"], "pkg.core.Loader.load")

    def test_underscore_module_path_is_not_public(self):
        result = walk({
            "__init__.py": "",
            "_internal.py": """
                from .core import target

                def helper():
                    target()
            """,
            "core.py": """
                def target():
                    pass
            """,
        }, ("pkg.core.target", "function"))
        self.assertEqual(names(result), ["pkg.core.target"])

    def test_vulnerable_public_function_is_its_own_entry_point(self):
        result = walk({
            "__init__.py": "",
            "core.py": """
                def run():
                    pass
            """,
        }, ("pkg.core.run", "function"))
        self.assertEqual(result["entry_points"], [{
            "name": "pkg.core.run", "defined_as": "pkg.core.run", "confidence": "high",
            "path": ["pkg.core.run"],
        }])

    def test_self_and_super_method_calls_resolve_through_bases(self):
        result = walk({
            "__init__.py": "from .c import Base, Child\n",
            "c.py": """
                class Base:
                    def m(self):
                        self._v()

                    def _v(self):
                        pass

                    def start(self):
                        pass

                class Child(Base):
                    def run(self):
                        self.m()

                    def start(self):
                        super().start()
            """,
        }, ("pkg.c.Base._v", "method"), ("pkg.c.Base.start", "method"))
        entries = by_name(result)
        self.assertEqual(entries["pkg.Child.run"]["path"],
                         ["pkg.c.Child.run", "pkg.c.Base.m", "pkg.c.Base._v"])
        self.assertEqual(entries["pkg.Child.run"]["confidence"], "high")
        self.assertEqual(entries["pkg.Base.m"]["path"], ["pkg.c.Base.m", "pkg.c.Base._v"])
        self.assertEqual(entries["pkg.Child.start"]["path"], ["pkg.c.Child.start", "pkg.c.Base.start"])
        self.assertEqual(entries["pkg.Child.start"]["confidence"], "high")

    def test_instantiation_is_an_edge_to_init(self):
        result = walk({
            "__init__.py": "",
            "c.py": """
                class Cls:
                    def __init__(self):
                        self._v()

                    def _v(self):
                        pass

                def make():
                    return Cls()
            """,
        }, ("pkg.c.Cls._v", "method"))
        self.assertEqual(names(result), ["pkg.c.Cls", "pkg.c.make"])
        entries = by_name(result)
        self.assertEqual(entries["pkg.c.Cls"]["defined_as"], "pkg.c.Cls.__init__")
        self.assertEqual(entries["pkg.c.make"]["path"],
                         ["pkg.c.make", "pkg.c.Cls.__init__", "pkg.c.Cls._v"])
        self.assertEqual(entries["pkg.c.make"]["confidence"], "high")

    def test_instantiation_without_own_init_goes_to_base_init_or_class(self):
        _, graph = graph_of({
            "__init__.py": "",
            "c.py": """
                class Base:
                    def __init__(self):
                        pass

                class Child(Base):
                    pass

                class Plain:
                    pass

                def make():
                    Child()
                    Plain()
            """,
        })
        self.assertEqual(graph.callers["pkg.c.Base.__init__"], [("pkg.c.make", "high")])
        self.assertEqual(graph.callers["pkg.c.Plain"], [("pkg.c.make", "high")])
        self.assertEqual(graph.bases, {"pkg.c.Base": [], "pkg.c.Child": ["pkg.c.Base"], "pkg.c.Plain": []})

    def test_unresolved_method_call_is_medium_edge(self):
        src, graph = graph_of({
            "__init__.py": "",
            "c.py": """
                class A:
                    def m(self):
                        pass

                class B:
                    def m(self):
                        pass

                def go(x):
                    x.m()
            """,
        })
        self.assertEqual(graph.callers["pkg.c.A.m"], [("pkg.c.go", "medium")])
        self.assertEqual(graph.callers["pkg.c.B.m"], [("pkg.c.go", "medium")])
        result = entrypoints.walk(src, "pkg", [{"name": "pkg.c.A.m", "kind": "method"}])
        entries = by_name(result)
        self.assertEqual(entries["pkg.c.go"]["confidence"], "medium")
        self.assertEqual(entries["pkg.c.go"]["path"], ["pkg.c.go", "pkg.c.A.m"])
        self.assertEqual(entries["pkg.c.A.m"]["confidence"], "high")

    def test_value_reference_is_not_an_edge(self):
        src, graph = graph_of({
            "__init__.py": "",
            "f.py": """
                import functools

                def _v():
                    pass

                TABLE = {"a": _v}

                @functools.lru_cache()
                def deco_user():
                    return [_v, sorted([], key=_v)]
            """,
        })
        self.assertEqual(graph.callers, {})
        self.assertEqual(graph.references, {})
        result = entrypoints.walk(src, "pkg", [{"name": "pkg.f._v", "kind": "function"}])
        self.assertEqual(result["entry_points"], [])
        self.assertEqual(result["reasons"], [])

    def test_duplicate_module_keeps_parsing_copy(self):
        # Review Focus 1: a lib/ copy with a Python 2 print, the lib3/ copy is used.
        src = [
            {"module": "pkg", "path": "lib/pkg/__init__.py", "source": ""},
            {"module": "pkg.core", "path": "lib/pkg/core.py",
             "source": "def _v():\n    print 'x'\n\ndef run():\n    _v()\n"},
            {"module": "pkg", "path": "lib3/pkg/__init__.py", "source": ""},
            {"module": "pkg.core", "path": "lib3/pkg/core.py",
             "source": "def _v():\n    print('x')\n\ndef run():\n    _v()\n"},
        ]
        graph = entrypoints.build_graph(src, "pkg")
        self.assertEqual(len(graph.notes), 2)
        self.assertRegex(graph.notes[0], r"^lib/pkg/core\.py: does not parse \(line 2: .+\), skipped$")
        self.assertEqual(graph.notes[1], "lib3/pkg/__init__.py: duplicate module pkg, skipped")
        self.assertEqual(graph.defs["pkg.core.run"],
                         {"kind": "function", "module": "pkg.core", "file": "lib3/pkg/core.py", "line": 4})
        result = entrypoints.walk(src, "pkg", [{"name": "pkg.core._v", "kind": "function"}])
        self.assertEqual(names(result), ["pkg.core.run"])
        self.assertEqual(result["notes"], graph.notes)

    def test_module_level_call_makes_no_edge(self):
        src, graph = graph_of({
            "__init__.py": "",
            "c.py": """
                def _v():
                    pass

                _v()

                class Cls:
                    _v()

                    def m(self):
                        pass
            """,
        })
        self.assertEqual(graph.callers, {})
        result = entrypoints.walk(src, "pkg", [{"name": "pkg.c._v", "kind": "function"}])
        self.assertEqual(result["entry_points"], [])


class GraphTest(unittest.TestCase):
    def test_defs_public_and_module_attribute_calls(self):
        _, graph = graph_of({
            "__init__.py": "from .c import Cls\n",
            "c.py": """
                class Cls:
                    def __init__(self):
                        pass

                    def __call__(self):
                        pass

                    def _hidden(self):
                        def nested():
                            pass

                def _f():
                    pass
            """,
            "use.py": """
                import pkg.c
                from . import c as cmod

                def a():
                    pkg.c._f()
                    cmod.Cls._hidden(None)
            """,
        })
        self.assertEqual(sorted(graph.defs), [
            "pkg.c.Cls", "pkg.c.Cls.__call__", "pkg.c.Cls.__init__", "pkg.c.Cls._hidden",
            "pkg.c._f", "pkg.use.a",
        ])
        self.assertEqual(graph.defs["pkg.c.Cls._hidden"],
                         {"kind": "method", "module": "pkg.c", "file": "pkg/c.py", "line": 9})
        self.assertEqual(graph.public, {
            "pkg.c.Cls": "pkg.Cls",
            "pkg.c.Cls.__init__": "pkg.Cls",
            "pkg.c.Cls.__call__": "pkg.Cls.__call__",
            "pkg.use.a": "pkg.use.a",
        })
        self.assertEqual(graph.callers["pkg.c._f"], [("pkg.use.a", "high")])
        self.assertEqual(graph.callers["pkg.c.Cls._hidden"], [("pkg.use.a", "high")])


if __name__ == "__main__":
    unittest.main()
