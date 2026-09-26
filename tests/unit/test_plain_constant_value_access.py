"""
Guard against calling `.value` on plain string-constant classes.

Regression: agentic_explorer passed `ScreenType.UNKNOWN.value` to the
screenshot manager. ScreenType is a plain class of str constants, not an Enum,
so the first observed screen of every run with screenshots enabled raised
AttributeError and killed UI exploration ("Fatal loop error").
"""

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROOTS = [REPO / "shared" / "sudarshan_core", REPO / "backend" / "app", REPO / "analysis-engine" / "app"]


def _trees():
    for root in ROOTS:
        for path in root.rglob("*.py"):
            yield path, ast.parse(path.read_bytes().decode("utf-8"))


def _plain_constant_classes(trees):
    names = set()
    for _, tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if any("Enum" in ast.unparse(b) for b in node.bases):
                continue
            assigns = [s for s in node.body if isinstance(s, (ast.Assign, ast.AnnAssign))]
            if assigns and all(
                isinstance(getattr(s, "value", None), ast.Constant) and isinstance(s.value.value, str)
                for s in assigns
            ):
                names.add(node.name)
    return names


def test_every_source_file_is_utf8_python():
    # A UTF-16 sudarshan_core/config/__init__.py made the package unimportable.
    for _path, _tree in _trees():
        pass


def test_no_value_access_on_plain_constant_classes():
    trees = list(_trees())
    plain = _plain_constant_classes(trees)
    offenders = []
    for path, tree in trees:
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "value"
                and isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id in plain
            ):
                offenders.append(f"{path.relative_to(REPO)}:{node.lineno} {ast.unparse(node)}")
    assert not offenders, "str constants have no .value:\n" + "\n".join(offenders)


def test_screen_type_is_plain_string():
    from sudarshan_core.engines.agentic.screen_classifier import ScreenType

    assert isinstance(ScreenType.UNKNOWN, str)
