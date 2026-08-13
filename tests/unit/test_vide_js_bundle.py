"""UI extraction from bundled JavaScript (Capacitor / React clones)."""

from sudarshan_core.engines.vide.js_bundle import (
    build_bundle_ast,
    extract_jsx_tags,
    extract_ui_strings,
    iter_string_literals,
    profile_from_js_bundle,
)
from sudarshan_core.engines.vide.view_ast import ROLE_BUTTON, ROLE_INPUT

# Shape a Vite build actually produces: minified, template literals, one line.
MINIFIED = (
    "(0,j.jsx)(`h1`,{children:`YONO SBI`}),"
    "(0,j.jsx)(ur,{label:`Username`,placeholder:`Enter username`}),"
    "(0,j.jsx)(ur,{label:`Password`,type:`password`}),"
    "(0,j.jsx)(`button`,{onClick:()=>e(`/mpin`),children:`Login`}),"
    "(0,j.jsx)(`input`,{}),(0,j.jsxs)(`div`,{children:`Available Balance`})"
)


def test_extracts_template_literal_ui_strings():
    found = extract_ui_strings(MINIFIED)
    for expected in ("YONO SBI", "Username", "Login", "Available Balance"):
        assert expected in found, expected


def test_rejects_code_tokens():
    found = extract_ui_strings(MINIFIED)
    for noise in ("/mpin", "password", "children", "onClick"):
        assert noise not in found, noise


def test_long_literal_does_not_desynchronise_pairing():
    """
    Regression: a bounded regex skipped over-long literals, so their closing
    backtick was read as an opening one and every later literal was mispaired.
    Framework code carries the long literals and is bundled first, so this
    silently dropped the entire application's UI text.
    """
    long_literal = "x" * 400
    bundle = f"a=`{long_literal}`,b=`Login`,c=`Available Balance`"

    found = extract_ui_strings(bundle)
    assert "Login" in found
    assert "Available Balance" in found


def test_backslash_escape_does_not_desynchronise_pairing():
    bundle = r"a=`path\\to\\thing`,b=`Login`,c=`Transfer Funds`"
    found = extract_ui_strings(bundle)
    assert "Login" in found
    assert "Transfer Funds" in found


def test_iter_string_literals_handles_mixed_quotes():
    literals = list(iter_string_literals("""a=`one`,b="two",c='three'"""))
    assert literals == ["one", "two", "three"]


def test_unterminated_literal_is_not_fatal():
    assert "Login" in extract_ui_strings("a=`Login`,b=`unterminated")


def test_jsx_tags_and_roles():
    tags = extract_jsx_tags(MINIFIED)
    assert "button" in tags
    assert "input" in tags

    ast = build_bundle_ast(MINIFIED)
    assert ast is not None
    counts = ast.role_counts()
    assert counts.get(ROLE_BUTTON, 0) >= 1
    assert counts.get(ROLE_INPUT, 0) >= 1


def test_empty_bundle_is_safe():
    assert extract_ui_strings("") == []
    assert build_bundle_ast("") is None
    assert profile_from_js_bundle("").strings == []
