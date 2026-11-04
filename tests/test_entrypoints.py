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
                         ["pkg.Loader", "pkg.Loader.load", "pkg.load_all", "pkg.loader.load_one", "pkg.run"])
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

                    def go(self):
                        self._v()

                def make():
                    return Cls()
            """,
        }, ("pkg.c.Cls._v", "method"))
        # Cls is listed once, through __init__, although its method go is an entry point too.
        self.assertEqual(names(result), ["pkg.c.Cls", "pkg.c.Cls.go", "pkg.c.make"])
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
        self.assertEqual(graph.references, {"pkg.f._v": [
            {"file": "pkg/f.py", "line": 7, "context": "value in dict literal TABLE"},
            {"file": "pkg/f.py", "line": 11, "context": "element of list literal"},
            {"file": "pkg/f.py", "line": 11, "context": "argument to sorted"},
        ]})
        result = entrypoints.walk(src, "pkg", [{"name": "pkg.f._v", "kind": "function"}])
        self.assertEqual(result["entry_points"], [])
        self.assertEqual([r["kind"] for r in result["reasons"]], ["referenced_not_called"])

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
            "pkg.c.Cls.__call__": "pkg.Cls",
            "pkg.use.a": "pkg.use.a",
        })
        self.assertEqual(graph.callers["pkg.c._f"], [("pkg.use.a", "high")])
        self.assertEqual(graph.callers["pkg.c.Cls._hidden"], [("pkg.use.a", "high")])

    def test_local_names_never_resolve_to_module_names(self):
        _, graph = graph_of({
            "__init__.py": "",
            "c.py": """
                class Loader:
                    def __init__(self, stream):
                        pass

                    def m(self):
                        pass

                def load(stream, Loader=None):
                    Loader(stream)

                def run():
                    run = print
                    run()

                def go(Loader):
                    Loader.m()

                def scoped():
                    for helper in []:
                        helper()
                    with open("f") as fh:
                        fh()
                    try:
                        pass
                    except Exception as err:
                        err()
                    global Loader
                    Loader(None)

                def helper():
                    pass

                def fh():
                    pass

                def err():
                    pass
            """,
        })
        self.assertEqual(graph.callers, {
            "pkg.c.Loader.__init__": [("pkg.c.scoped", "high")],
            "pkg.c.Loader.m": [("pkg.c.go", "medium")],
        })

    def test_star_import_in_any_module_binds_names_and_bases(self):
        src, graph = graph_of({
            "__init__.py": "",
            "base.py": """
                class Reader:
                    def peek(self):
                        pass

                class _Hidden:
                    pass
            """,
            "loader.py": """
                from .base import *

                class Loader(Reader):
                    def load(self):
                        self.peek()
            """,
        })
        self.assertEqual(graph.bases["pkg.loader.Loader"], ["pkg.base.Reader"])
        self.assertEqual(graph.callers["pkg.base.Reader.peek"], [("pkg.loader.Loader.load", "high")])
        result = entrypoints.walk(src, "pkg", [{"name": "pkg.base.Reader.peek", "kind": "method"}])
        self.assertEqual(by_name(result)["pkg.loader.Loader.load"]["confidence"], "high")


    def test_reference_contexts(self):
        _, graph = graph_of({
            "__init__.py": "",
            "c.py": """\
                def f():
                    pass

                LIST = [f]
                PAIR = (f, 1)
                BAG = {f}
                alias = f
                OPTIONS = [{"k": f}]

                def g(cb=f, *, other=f):
                    return f

                def h(f):
                    return {"k": f}

                x = f if True else None
                obj.attr = f
            """,
        })
        self.assertEqual(graph.references, {"pkg.c.f": [
            {"file": "pkg/c.py", "line": 4, "context": "element of list literal"},
            {"file": "pkg/c.py", "line": 5, "context": "element of tuple literal"},
            {"file": "pkg/c.py", "line": 6, "context": "element of set literal"},
            {"file": "pkg/c.py", "line": 7, "context": "assigned to alias"},
            {"file": "pkg/c.py", "line": 8, "context": "value in dict literal"},
            {"file": "pkg/c.py", "line": 10, "context": "default argument of g"},
            {"file": "pkg/c.py", "line": 10, "context": "default argument of g"},
            {"file": "pkg/c.py", "line": 11, "context": "returned from g"},
            {"file": "pkg/c.py", "line": 16, "context": "referenced"},
            {"file": "pkg/c.py", "line": 17, "context": "assigned to obj.attr"},
        ]})

    def test_parser_recursion_error_is_a_does_not_parse_note(self):
        # Python 3.14 reports the reviewer's nested-parentheses example as a
        # SyntaxError (tokenizer limit); a long flat sum overflows the
        # compiler's stack instead and raises RecursionError.
        src = [
            {"module": "pkg", "path": "pkg/__init__.py", "source": ""},
            {"module": "pkg.deep", "path": "pkg/deep.py", "source": "X = " + "1+" * 100000 + "1\n"},
            {"module": "pkg.nested", "path": "pkg/nested.py",
             "source": "X = " + "(" * 2000 + "1" + ")" * 2000 + "\n"},
        ]
        graph = entrypoints.build_graph(src, "pkg")
        self.assertEqual(graph.notes[0], "pkg/deep.py: does not parse (RecursionError), skipped")
        self.assertRegex(graph.notes[1], r"^pkg/nested\.py: does not parse \(.+\), skipped$")
        self.assertEqual(sorted(graph.modules), ["pkg"])

    def test_calls_in_nested_scopes_are_references_not_edges(self):
        src, graph = graph_of({
            "__init__.py": "",
            "core.py": """\
                def _vuln(x):
                    pass
                REG = {}
                def register(tag, fn):
                    REG[tag] = fn
                def setup():
                    register('t', lambda n: _vuln(n))
                def setup2():
                    def inner(n):
                        return _vuln(n)
                    register('u', inner)
                def setup3():
                    def inner(cb=_vuln(1)):
                        pass
                    class Local:
                        _vuln(2)
            """,
        })
        self.assertEqual(graph.callers["pkg.core._vuln"], [("pkg.core.setup3", "high")])
        self.assertEqual(sorted(graph.callers["pkg.core.register"]),
                         [("pkg.core.setup", "high"), ("pkg.core.setup2", "high")])
        self.assertEqual(graph.references["pkg.core._vuln"], [
            {"file": "pkg/core.py", "line": 7, "context": "called inside a nested scope of setup"},
            {"file": "pkg/core.py", "line": 10, "context": "called inside a nested scope of setup2"},
            {"file": "pkg/core.py", "line": 16, "context": "called inside a nested scope of setup3"},
        ])

    def test_method_value_uses_through_self_and_class_body_are_references(self):
        _, graph = graph_of({
            "__init__.py": "",
            "core.py": """\
                class Base:
                    def inherited(self):
                        pass

                class P(Base):
                    def __init__(self):
                        self.table = {'a': self.handle_a}
                        self.run = lambda: self.handle_b
                        self.handle_a()
                        self.data = self.missing

                    @classmethod
                    def make(cls):
                        return cls.handle_b

                    def handle_a(self):
                        pass

                    def handle_b(self):
                        pass

                    DISPATCH = {'a': handle_a, 'i': inherited}

                    def defaults(self, cb=handle_b):
                        def handle_a():
                            return handle_a
                        return handle_a
            """,
        })
        self.assertEqual(graph.references, {
            "pkg.core.Base": [{"file": "pkg/core.py", "line": 5, "context": "referenced"}],
            "pkg.core.P.handle_a": [
                {"file": "pkg/core.py", "line": 7, "context": "value in dict literal"},
                {"file": "pkg/core.py", "line": 22, "context": "value in dict literal DISPATCH"},
            ],
            "pkg.core.P.handle_b": [
                {"file": "pkg/core.py", "line": 8, "context": "referenced"},
                {"file": "pkg/core.py", "line": 14, "context": "returned from make"},
                {"file": "pkg/core.py", "line": 24, "context": "default argument of defaults"},
            ],
            "pkg.core.Base.inherited": [
                {"file": "pkg/core.py", "line": 22, "context": "value in dict literal DISPATCH"},
            ],
        })
        self.assertEqual(graph.callers["pkg.core.P.handle_a"], [("pkg.core.P.__init__", "high")])

    def test_deep_expression_does_not_stop_the_reference_scan(self):
        source = 'def f():\n    pass\nTABLE = {"k": f}\nX = ' + " + ".join(["1"] * 1500) + "\n"
        src = [
            {"module": "pkg", "path": "pkg/__init__.py", "source": ""},
            {"module": "pkg.c", "path": "pkg/c.py", "source": source},
        ]
        graph = entrypoints.build_graph(src, "pkg")
        self.assertEqual(graph.references, {"pkg.c.f": [
            {"file": "pkg/c.py", "line": 3, "context": "value in dict literal TABLE"},
        ]})

    def test_inherited_method_named_under_shortest_public_subclass(self):
        result = walk({
            "__init__.py": "from .sessions import Session as Session\n",
            "sessions.py": """
                class Mixin:
                    def resolve(self):
                        self._v()

                    def _v(self):
                        pass

                class Session(Mixin):
                    pass

                class Other:
                    def ping(self):
                        pass
            """,
        }, ("pkg.sessions.Mixin._v", "method"))
        self.assertEqual(result["entry_points"], [{
            "name": "pkg.Session", "defined_as": "pkg.sessions.Session", "confidence": "high",
            "path": ["pkg.sessions.Session", "pkg.sessions.Mixin.resolve", "pkg.sessions.Mixin._v"],
        }, {
            "name": "pkg.Session.resolve", "defined_as": "pkg.sessions.Mixin.resolve",
            "confidence": "high", "path": ["pkg.sessions.Mixin.resolve", "pkg.sessions.Mixin._v"],
        }])

    def test_overridden_method_keeps_the_defining_class_path(self):
        _, graph = graph_of({
            "__init__.py": "from .sessions import Session as Session\n",
            "sessions.py": """
                class Mixin:
                    def __init__(self):
                        pass

                    def resolve(self):
                        pass

                class Session(Mixin):
                    def resolve(self):
                        pass
            """,
        })
        self.assertEqual(graph.public["pkg.sessions.Mixin.resolve"], "pkg.sessions.Mixin.resolve")
        self.assertEqual(graph.public["pkg.sessions.Session.resolve"], "pkg.Session.resolve")
        self.assertEqual(graph.public["pkg.sessions.Mixin.__init__"], "pkg.Session")


class ReasonTest(unittest.TestCase):
    def test_dict_value_registration_is_referenced_not_called(self):
        result = walk({
            "__init__.py": "",
            "filters.py": """\
                def do_attr(obj):
                    return obj
                FILTERS = {"attr": do_attr}

                def table(do_attr):
                    return {"attr": do_attr}
            """,
        }, ("pkg.filters.do_attr", "function"))
        self.assertEqual(result["reasons"], [{
            "item": "pkg.filters.do_attr", "kind": "referenced_not_called", "file": "pkg/filters.py",
            "references": [{"file": "pkg/filters.py", "line": 3, "context": "value in dict literal FILTERS"}],
            "dead_ends": [],
        }])
        self.assertEqual(names(result), ["pkg.filters.do_attr"])
        self.assertEqual(result["notes"], [])

    def test_argument_registration_names_the_callee(self):
        src, graph = graph_of({
            "__init__.py": "",
            "c.py": """\
                class Cls:
                    @classmethod
                    def add_multi_constructor(cls, tag, fn):
                        pass

                    def construct_new(self, node):
                        pass

                Cls.add_multi_constructor("tag", Cls.construct_new)
                Cls.add_multi_constructor("tag", fn=Cls.construct_new)
            """,
        })
        expected = [
            {"file": "pkg/c.py", "line": 9, "context": "argument to add_multi_constructor"},
            {"file": "pkg/c.py", "line": 10, "context": "argument to add_multi_constructor"},
        ]
        self.assertEqual(graph.references, {"pkg.c.Cls.construct_new": expected})
        result = entrypoints.walk(src, "pkg", [{"name": "pkg.c.Cls.construct_new", "kind": "method"}])
        self.assertEqual(result["reasons"], [{
            "item": "pkg.c.Cls.construct_new", "kind": "referenced_not_called", "file": "pkg/c.py",
            "references": expected, "dead_ends": [],
        }])

    def test_dead_end_chain_lists_registered_roots(self):
        result = walk({
            "__init__.py": "",
            "c.py": """\
                def set_state(obj):
                    pass

                class Cls:
                    @classmethod
                    def add_multi_constructor(cls, tag, fn):
                        pass

                    def apply(self, node):
                        set_state(node)

                Cls.add_multi_constructor("tag", Cls.apply)
            """,
        }, ("pkg.c.set_state", "function"))
        self.assertEqual(result["reasons"], [{
            "item": "pkg.c.set_state", "kind": "dead_end_chain", "file": "pkg/c.py", "references": [],
            "dead_ends": [{"name": "pkg.c.Cls.apply", "references": [
                {"file": "pkg/c.py", "line": 12, "context": "argument to add_multi_constructor"},
            ]}],
        }])
        self.assertEqual(names(result), ["pkg.c.Cls", "pkg.c.Cls.apply", "pkg.c.set_state"])

    def test_nested_scope_registration_is_referenced_not_called(self):
        result = walk({
            "__init__.py": "",
            "core.py": """\
                def _vuln(x):
                    pass
                REG = {}
                def register(tag, fn):
                    REG[tag] = fn
                def setup():
                    register('t', lambda n: _vuln(n))
                def setup2():
                    def inner(n):
                        return _vuln(n)
                    register('u', inner)
            """,
        }, ("pkg.core._vuln", "function"))
        self.assertEqual(result["reasons"], [{
            "item": "pkg.core._vuln", "kind": "referenced_not_called", "file": "pkg/core.py",
            "references": [
                {"file": "pkg/core.py", "line": 7, "context": "called inside a nested scope of setup"},
                {"file": "pkg/core.py", "line": 10, "context": "called inside a nested scope of setup2"},
            ],
            "dead_ends": [],
        }])
        self.assertNotIn("pkg.core.setup", names(result))
        self.assertNotIn("pkg.core.setup2", names(result))
        self.assertEqual(result["entry_points"], [])

    def test_self_dispatch_table_makes_a_dead_end(self):
        files = {
            "__init__.py": "",
            "core.py": """\
                class P:
                    def __init__(self):
                        self.table = {'a': self.handle_a}
                    def process(self, k):
                        return self.table[k]()
                    def handle_a(self):
                        return _parse()
                def _parse():
                    pass
            """,
        }
        table = {"file": "pkg/core.py", "line": 3, "context": "value in dict literal"}
        result = walk(files, ("pkg.core._parse", "function"))
        self.assertEqual(result["reasons"], [{
            "item": "pkg.core._parse", "kind": "dead_end_chain", "file": "pkg/core.py", "references": [],
            "dead_ends": [{"name": "pkg.core.P.handle_a", "references": [table]}],
        }])
        result = walk(files, ("pkg.core.P.handle_a", "method"))
        self.assertEqual(result["reasons"], [{
            "item": "pkg.core.P.handle_a", "kind": "referenced_not_called", "file": "pkg/core.py",
            "references": [table], "dead_ends": [],
        }])

    def test_class_body_dispatch_table_makes_a_dead_end(self):
        files = {
            "__init__.py": "",
            "core.py": """\
                class P:
                    def handle_a(self, n):
                        return _parse(n)
                    DISPATCH = {'a': handle_a}
                    def process(self, k, n):
                        return self.DISPATCH[k](self, n)
                def _parse(n):
                    pass
            """,
        }
        table = {"file": "pkg/core.py", "line": 4, "context": "value in dict literal DISPATCH"}
        result = walk(files, ("pkg.core._parse", "function"))
        self.assertEqual(result["reasons"], [{
            "item": "pkg.core._parse", "kind": "dead_end_chain", "file": "pkg/core.py", "references": [],
            "dead_ends": [{"name": "pkg.core.P.handle_a", "references": [table]}],
        }])
        result = walk(files, ("pkg.core.P.handle_a", "method"))
        self.assertEqual(result["reasons"], [{
            "item": "pkg.core.P.handle_a", "kind": "referenced_not_called", "file": "pkg/core.py",
            "references": [table], "dead_ends": [],
        }])

    def test_module_level_item_is_a_reason(self):
        result = walk({"__init__.py": "", "c.py": "X = 1\n"},
                      ("pkg.c", "module_level"), ("pkg.gone", "module_level"))
        self.assertEqual(result["reasons"], [
            {"item": "pkg.c", "kind": "module_level", "file": "pkg/c.py", "references": [], "dead_ends": []},
            {"item": "pkg.gone", "kind": "module_level", "file": None, "references": [], "dead_ends": []},
        ])
        self.assertEqual(result["entry_points"], [])

    def test_class_level_public_class_is_connected_private_is_not(self):
        files = {
            "__init__.py": "",
            "c.py": """\
                class Retry:
                    DEFAULT = 3

                class _Pool:
                    SIZE = 1

                def connect(retries=Retry, pool=_Pool):
                    pass
            """,
        }
        public = walk(files, ("pkg.c.Retry", "class_level"))
        self.assertEqual(public["reasons"], [])
        self.assertEqual(public["entry_points"], [{
            "name": "pkg.c.Retry", "defined_as": "pkg.c.Retry", "confidence": "high",
            "path": ["pkg.c.Retry"],
        }])
        private = walk(files, ("pkg.c._Pool", "class_level"))
        self.assertEqual(private["reasons"], [{
            "item": "pkg.c._Pool", "kind": "class_level", "file": "pkg/c.py",
            "references": [{"file": "pkg/c.py", "line": 7, "context": "default argument of connect"}],
            "dead_ends": [],
        }])
        self.assertEqual(private["entry_points"], [])

    def test_self_only_public_function_is_exempt_with_note(self):
        result = walk({
            "__init__.py": "",
            "c.py": """
                def run():
                    pass
            """,
        }, ("pkg.c.run", "function"))
        self.assertEqual(result["reasons"], [])
        self.assertEqual(names(result), ["pkg.c.run"])
        self.assertEqual(result["entry_points"][0]["path"], ["pkg.c.run"])
        self.assertEqual(result["notes"],
                         ["self-only entry point: pkg.c.run has no caller or reference inside the package"])

    def test_method_with_no_caller_or_reference_is_no_reference(self):
        result = walk({
            "__init__.py": "",
            "c.py": """
                class Cls:
                    def m(self):
                        pass

                def _f():
                    pass
            """,
        }, ("pkg.c.Cls.m", "method"), ("pkg.c._f", "function"))
        self.assertEqual(result["reasons"], [
            {"item": "pkg.c.Cls.m", "kind": "no_reference", "file": "pkg/c.py", "references": [], "dead_ends": []},
            {"item": "pkg.c._f", "kind": "no_reference", "file": "pkg/c.py", "references": [], "dead_ends": []},
        ])
        self.assertEqual(names(result), ["pkg.c.Cls", "pkg.c.Cls.m"])
        self.assertEqual(result["notes"], [])
        # The exemption follows the graph's kind, not the item's declared kind.
        result = walk({
            "__init__.py": "",
            "c.py": """
                class Cls:
                    def m(self):
                        pass
            """,
        }, ("pkg.c.Cls.m", "function"))
        self.assertEqual([r["kind"] for r in result["reasons"]], ["no_reference"])
        self.assertEqual(result["notes"], [])

    def test_item_missing_from_tree_is_no_reference_with_detail(self):
        # Review Focus 2
        result = walk({"__init__.py": "", "c.py": "X = 1\n"}, ("pkg.c.gone", "function"))
        self.assertEqual(result["reasons"], [{
            "item": "pkg.c.gone", "kind": "no_reference", "file": None, "references": [], "dead_ends": [],
            "detail": "not defined in the analysed tree",
        }])
        self.assertEqual(result["entry_points"], [])

    def test_cycle_without_root_is_dead_end_with_empty_list(self):
        # Review Focus 3
        result = walk({
            "__init__.py": "",
            "c.py": """
                def _a():
                    _b()

                def _b():
                    _a()
            """,
        }, ("pkg.c._a", "function"))
        self.assertEqual(result["reasons"], [{
            "item": "pkg.c._a", "kind": "dead_end_chain", "file": "pkg/c.py", "references": [],
            "dead_ends": [], "detail": "no root: every caller is itself called",
        }])

    def test_connected_item_has_no_reason_even_with_a_dead_chain(self):
        result = walk({
            "__init__.py": "",
            "c.py": """
                def _v():
                    pass

                def run():
                    _v()

                class Cls:
                    @classmethod
                    def reg(cls, tag, fn):
                        pass

                    def apply(self):
                        _v()

                Cls.reg("tag", Cls.apply)
            """,
        }, ("pkg.c._v", "function"))
        self.assertEqual(result["reasons"], [])
        self.assertEqual(names(result), ["pkg.c.Cls", "pkg.c.Cls.apply", "pkg.c.run"])

    def test_medium_only_chain_is_connected(self):
        result = walk({
            "__init__.py": "",
            "c.py": """
                class A:
                    def m(self):
                        pass

                def go(x):
                    x.m()
            """,
        }, ("pkg.c.A.m", "method"))
        self.assertEqual(result["reasons"], [])
        self.assertEqual(by_name(result)["pkg.c.go"]["confidence"], "medium")

    def test_decorator_is_not_a_reference(self):
        # Cls.run's only "use" is inside a decorator; it stays a clean root.
        src, graph = graph_of({
            "__init__.py": "",
            "c.py": """
                def register(fn):
                    return lambda g: g

                def _v():
                    pass

                class Cls:
                    @property
                    def run(self):
                        _v()

                @register(Cls.run)
                def other():
                    pass
            """,
        })
        self.assertEqual(graph.references, {})
        result = entrypoints.walk(src, "pkg", [{"name": "pkg.c._v", "kind": "function"}])
        self.assertEqual(result["reasons"], [])
        self.assertEqual(names(result), ["pkg.c.Cls", "pkg.c.Cls.run"])


if __name__ == "__main__":
    unittest.main()
