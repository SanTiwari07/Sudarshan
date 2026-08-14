"""Multi-source extraction: web bundle, DEX constant pool, tag normalisation.

Each of these exists to close a specific false negative, so the tests are
written as "this app shape used to extract nothing".
"""

import struct

import pytest

from sudarshan_core.engines.vide.dex_strings import (
    is_ui_string,
    iter_dex_strings,
    mine_banking_strings,
    mine_from_decode_dir,
    score_banking_string,
)
from sudarshan_core.engines.vide.layout_extractor import (
    extract_css_colors,
    extract_from_decode_dir,
    extract_html_strings,
    extract_web_bundle,
)
from sudarshan_core.engines.vide.view_ast import (
    ROLE_BUTTON,
    ROLE_CONTAINER,
    ROLE_INPUT,
    ROLE_TEXT,
    normalize_view_sequence,
    normalize_view_tag,
)

# ── Capacitor / web bundle ─────────────────────────────────────────────────

INDEX_HTML = """<!doctype html>
<html><head><title>BOI Mobile</title></head>
<body>
  <div id="root">
    <h1>Welcome to BOI Mobile</h1>
    <input placeholder="Mobile Number / User ID" />
    <input type="password" placeholder="Password" />
    <button>Proceed</button>
  </div>
</body></html>
"""

TOKENS_CSS = """
:root {
  --color-primary: #005A9C;
  --color-secondary: #F26522;
  --surface: rgb(242, 245, 250);
  --short: #ABC;
}
.btn { background: var(--color-primary); }
"""

BUNDLE_JS = (
    "const e=[`Enter 6-digit MPIN to login`,`Forgot MPIN?`,`Available Balance`,"
    "`Pay Bills`];function r(){return jsx(`div`,{children:jsx(`input`,{})})}"
)


@pytest.fixture
def capacitor_apk(tmp_path):
    """A decoded APK laid out the way a Capacitor build actually is."""
    public = tmp_path / "assets" / "public"
    (public / "assets").mkdir(parents=True)
    (public / "index.html").write_text(INDEX_HTML, encoding="utf-8")
    (public / "assets" / "index-abc123.css").write_text(TOKENS_CSS, encoding="utf-8")
    (public / "assets" / "index-abc123.js").write_text(BUNDLE_JS, encoding="utf-8")
    # Bridge shims must be ignored: they are identical in every Capacitor app.
    (public / "cordova.js").write_text("var cordova = {};" * 40, encoding="utf-8")
    return tmp_path


def test_web_bundle_recovers_ui_strings(capacitor_apk):
    profile = extract_web_bundle(capacitor_apk)
    lowered = [s.lower() for s in profile.strings]
    assert "welcome to boi mobile" in lowered
    assert "mobile number / user id" in lowered
    assert "password" in lowered
    assert "enter 6-digit mpin to login" in lowered


def test_web_bundle_recovers_brand_palette(capacitor_apk):
    profile = extract_web_bundle(capacitor_apk)
    assert "#005a9c" in profile.color_palette
    assert "#f26522" in profile.color_palette


def test_decode_dir_falls_back_to_web_bundle_when_res_is_empty(capacitor_apk):
    """`res/layout` in a Capacitor APK holds only the bridge activity."""
    profile = extract_from_decode_dir(capacitor_apk)
    assert profile.strings
    assert profile.colors
    assert "web_bundle" in profile.source


def test_css_colors_expand_short_hex_and_rgb():
    colors = extract_css_colors(TOKENS_CSS)
    assert "#005a9c" in colors
    assert "#aabbcc" in colors        # #ABC expanded
    assert "#f2f5fa" in colors        # rgb(242, 245, 250) converted


def test_html_strings_include_placeholder_copy():
    strings = [s.lower() for s in extract_html_strings(INDEX_HTML)]
    assert "mobile number / user id" in strings
    assert "proceed" in strings


# ── DEX constant pool ──────────────────────────────────────────────────────


def _build_dex(strings):
    """A minimal but structurally valid DEX carrying the given literals."""
    header_size = 0x70
    table_off = header_size
    data_off = table_off + 4 * len(strings)

    encoded = []
    offsets = []
    cursor = data_off
    for value in strings:
        raw = value.encode("utf-8")
        # string_data_item: uleb128 utf16_size (short here, so single byte)
        item = bytes([len(value)]) + raw + b"\x00"
        offsets.append(cursor)
        encoded.append(item)
        cursor += len(item)

    blob = bytearray(b"dex\n035\x00")
    blob.extend(b"\x00" * (header_size - len(blob)))
    struct.pack_into("<I", blob, 0x38, len(strings))
    struct.pack_into("<I", blob, 0x3C, table_off)
    for offset in offsets:
        blob.extend(struct.pack("<I", offset))
    for item in encoded:
        blob.extend(item)
    return bytes(blob)


def test_dex_string_table_is_parsed_exactly():
    literals = ["Available Balance", "Enter MPIN", "Ljava/lang/String;"]
    assert list(iter_dex_strings(_build_dex(literals))) == literals


def test_dex_mining_recovers_banking_labels(tmp_path):
    dex = tmp_path / "classes.dex"
    dex.write_bytes(
        _build_dex(
            [
                "Available Balance",
                "Enter 6-digit MPIN",
                "Ljava/lang/String;",
                "FragmentManager is already executing transactions",
                "TRANSACTION_notify",
                "AccountMetadataColumns",
                "Landroidx/fragment/app/Fragment;",
            ]
        )
    )
    mined = mine_from_decode_dir(tmp_path)
    assert "Available Balance" in mined
    assert "Enter 6-digit MPIN" in mined
    # Framework noise must not survive: it identifies no bank and would crowd
    # out real labels under the result cap.
    assert not any("Fragment" in s for s in mined)
    assert "TRANSACTION_notify" not in mined
    assert "AccountMetadataColumns" not in mined


def test_dex_mining_ranks_distinctive_terms_first(tmp_path):
    dex = tmp_path / "classes.dex"
    dex.write_bytes(_build_dex(["Payment Successful", "Enter UPI PIN"]))
    mined = mine_banking_strings([dex], limit=10)
    # "UPI PIN" identifies a banking app; "Payment" alone does not.
    assert mined[0] == "Enter UPI PIN"


def test_word_boundaries_prevent_substring_false_positives():
    """`m-?pin` without a boundary matches inside "du(mpin)g"."""
    assert score_banking_string("Failed dumping state") == 0
    assert score_banking_string("Enter MPIN") == 2


def test_banking_acronyms_survive_the_identifier_filter():
    for label in ("MPIN", "OTP", "UPI", "IFSC"):
        assert is_ui_string(label), label
    for identifier in ("ACCOUNT_STATUS_API", "AccountAccessor", "changepassword"):
        assert not is_ui_string(identifier), identifier


def test_corrupt_dex_degrades_to_printable_runs():
    blob = b"\x00\x01\x02Available Balance\x00\xff\xfeEnter MPIN\x00"
    recovered = list(iter_dex_strings(blob))
    assert any("Available Balance" in s for s in recovered)


# ── view tag normalisation ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "tag,role",
    [
        ("TextInputEditText", ROLE_INPUT),
        ("AppCompatEditText", ROLE_INPUT),
        ("EditText", ROLE_INPUT),
        ("input", ROLE_INPUT),
        ("com.google.android.material.button.MaterialButton", ROLE_BUTTON),
        ("Button", ROLE_BUTTON),
        ("button", ROLE_BUTTON),
        ("LinearLayout", ROLE_CONTAINER),
        ("div", ROLE_CONTAINER),
        ("TextView", ROLE_TEXT),
        ("p", ROLE_TEXT),
    ],
)
def test_differing_toolkits_map_to_one_role(tag, role):
    assert normalize_view_tag(tag) == role


def test_already_normalised_tokens_pass_through():
    """Corpus regionOrder entries are a normalised vocabulary of their own."""
    for token in ("HEADER", "PRIMARY_CONTENT", "NUMERIC_KEYPAD", ROLE_INPUT):
        assert normalize_view_tag(token) == token


def test_normalisation_is_idempotent():
    tags = ["TextInputEditText", "MaterialButton", "LinearLayout", "TextView"]
    once = normalize_view_sequence(tags)
    assert normalize_view_sequence(once) == once


def test_native_and_hybrid_login_screens_normalise_alike():
    native = ["LinearLayout", "TextInputEditText", "TextInputEditText", "MaterialButton"]
    hybrid = ["div", "input", "input", "button"]
    assert normalize_view_sequence(native) == normalize_view_sequence(hybrid)
