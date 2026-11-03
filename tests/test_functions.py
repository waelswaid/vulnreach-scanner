"""Unit tests for pipeline.functions: which functions a fix commit changed.

Run from the repository root:
    python -m unittest tests.test_functions
"""

import unittest

from pipeline import functions


def names(result, change=None):
    return [v["name"] for v in result["vulnerable"] if change is None or v["change"] == change]


class ChangedFunctionsTest(unittest.TestCase):
    def test_modified_method_named_fully_qualified(self):
        before = "class Foo:\n    def bar(self):\n        return 1\n"
        after = "class Foo:\n    def bar(self):\n        return 2\n"
        result = functions.changed_functions(before, after, [3], [3], "pkg.mod")
        self.assertEqual(result["added"], [])
        self.assertEqual(len(result["vulnerable"]), 1)
        entry = result["vulnerable"][0]
        self.assertEqual(entry["name"], "pkg.mod.Foo.bar")
        self.assertEqual(entry["kind"], "method")
        self.assertEqual(entry["change"], "modified")
        self.assertTrue(entry["evidence"])

    def test_added_function_excluded_but_recorded(self):
        before = "def a():\n    return 1\n"
        after = "def a():\n    return 1\n\n\ndef b():\n    return 2\n"
        result = functions.changed_functions(before, after, [], [4, 5, 6], "pkg.mod")
        self.assertEqual(result["vulnerable"], [])
        self.assertEqual(result["added"], ["pkg.mod.b"])

    def test_deleted_function_included(self):
        before = "def a():\n    return 1\n\n\ndef b():\n    return 2\n"
        after = "def a():\n    return 1\n"
        result = functions.changed_functions(before, after, [4, 5, 6], [], "pkg.mod")
        self.assertEqual(names(result, "deleted"), ["pkg.mod.b"])
        self.assertEqual(names(result, "modified"), [])
        self.assertEqual(result["vulnerable"][0]["kind"], "function")

    def test_docstring_only_change_excluded(self):
        before = 'def a():\n    """old"""\n    return 1\n'
        after = 'def a():\n    """new words"""\n    return 1\n'
        result = functions.changed_functions(before, after, [2], [2], "pkg.mod")
        self.assertEqual(result["vulnerable"], [])
        self.assertEqual(result["cosmetic"], ["pkg.mod.a"])

    def test_formatting_only_change_excluded(self):
        before = "def a(x):\n    return (x +\n            1)  # sum\n"
        after = "def a(x):\n    return x + 1\n"
        result = functions.changed_functions(before, after, [2, 3], [2], "pkg.mod")
        self.assertEqual(result["vulnerable"], [])

    def test_class_level_default_change_reported(self):
        before = "class Retry:\n    REMOVE = ['Authorization']\n\n    def go(self):\n        pass\n"
        after = "class Retry:\n    REMOVE = ['Authorization', 'Cookie']\n\n    def go(self):\n        pass\n"
        result = functions.changed_functions(before, after, [2], [2], "pkg.mod")
        self.assertEqual([(v["name"], v["kind"], v["change"]) for v in result["vulnerable"]],
                         [("pkg.mod.Retry", "class_level", "modified")])

    def test_module_level_constant_change_reported(self):
        before = "import re\nX = 1\n\n\ndef a():\n    return X\n"
        after = "import re\nimport os\nX = 2\n\n\ndef a():\n    return X\n"
        result = functions.changed_functions(before, after, [2], [2, 3], "pkg.mod")
        self.assertEqual([(v["name"], v["kind"], v["change"]) for v in result["vulnerable"]],
                         [("pkg.mod", "module_level", "modified")])

    def test_module_level_pure_addition_not_reported(self):
        before = "X = 1\n"
        after = "import re\nX = 1\n_re = re.compile('a')\n"
        result = functions.changed_functions(before, after, [], [1, 3], "pkg.mod")
        self.assertEqual(result["vulnerable"], [])

    def test_module_level_version_string_change_ignored(self):
        # certifi's fix commits bump __version__ in __init__.py; that is not vulnerable code.
        before = '"""certifi."""\nfrom .core import where\n__version__ = "2024.06.02"\n'
        after = '"""certifi."""\nfrom .core import where\n__version__ = "2024.07.04"\n'
        result = functions.changed_functions(before, after, [3], [3], "certifi")
        self.assertEqual(result["vulnerable"], [])

    def test_nested_function_maps_to_innermost(self):
        before = "def outer():\n    def inner():\n        return 1\n    return inner\n"
        after = "def outer():\n    def inner():\n        return 2\n    return inner\n"
        result = functions.changed_functions(before, after, [3], [3], "pkg.mod")
        self.assertEqual([(v["name"], v["kind"]) for v in result["vulnerable"]],
                         [("pkg.mod.outer.inner", "function")])

    def test_unparseable_source_is_skipped_with_note(self):
        before = "print 'python 2'\n"
        after = "print('python 3')\n"
        result = functions.changed_functions(before, after, [1], [1], "pkg.mod")
        self.assertEqual(result["vulnerable"], [])
        self.assertEqual(result["added"], [])
        self.assertTrue(any("parse" in note for note in result["notes"]))


if __name__ == "__main__":
    unittest.main()
