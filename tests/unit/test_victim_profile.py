"""
The Dumb Victim's identity: meaningful, coherent, and not a fingerprint.

Two requirements pull in opposite directions here and both are load-bearing:

* the data a form receives has to look like a person, or a validator rejects it
  and a journey that was never attempted is recorded as blocked (§P8);
* the identity must not be the same on every run, or a sample can recognise the
  analysis on one string compare and go dormant.

The resolution is a deterministic *template* with a per-run *instance*. These
tests pin both halves.
"""

import os
import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.credentials import (  # noqa: E402
    CredentialVault,
    all_secret_values,
)
from sudarshan_core.engines.agentic.field_constraints import (  # noqa: E402
    FieldConstraints,
    generate_value,
)
from sudarshan_core.engines.agentic.field_taxonomy import FieldType  # noqa: E402
from sudarshan_core.engines.agentic.victim_profile import (  # noqa: E402
    build_victim_profile,
    reset_profile_cache,
)

_ENV_KEYS = [
    "SUDARSHAN_VICTIM_DETERMINISTIC",
    "SUDARSHAN_VICTIM_PROFILE_FILE",
    "SUDARSHAN_VICTIM_EMAIL",
    "SUDARSHAN_VICTIM_CITY",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    reset_profile_cache()
    yield
    reset_profile_cache()


def _value(field_type: FieldType, profile, **kwargs) -> str:
    return generate_value(
        FieldConstraints(field_type=field_type, **kwargs), profile=profile,
    )


# ─── The profile is meaningful ───────────────────────────────────────────────

def test_synthetic_name_is_a_name_not_a_random_string():
    p = build_victim_profile()
    assert p.full_name == f"{p.first_name} {p.last_name}"
    # Two capitalised alphabetic words. "Analysis Kqmz" fails the second word.
    assert re.fullmatch(r"[A-Z][a-z]+ [A-Z][a-z]+", p.full_name), p.full_name


def test_synthetic_email_is_syntactically_valid_and_matches_the_person():
    p = build_victim_profile()
    assert re.fullmatch(r"[a-z]+\.[a-z]+\d*@[a-z0-9.\-]+\.[a-z]{2,}", p.email), p.email
    assert p.first_name.lower() in p.email
    assert p.last_name.lower() in p.email


def test_synthetic_email_stays_on_a_reserved_tld():
    """
    RFC 2606 `.test` cannot resolve and cannot receive mail.

    A real provider's domain would mean a sample exfiltrating its form
    contents, or triggering a password-reset flow, reached live infrastructure
    belonging to someone else.
    """
    assert build_victim_profile().email.endswith(".test")


def test_synthetic_phone_matches_the_indian_ten_digit_shape():
    phone = build_victim_profile().phone
    assert re.fullmatch(r"[6-9]\d{9}", phone), phone


def test_synthetic_address_is_coherent_with_city_and_state():
    p = build_victim_profile()
    assert p.city in p.address
    assert re.fullmatch(r"\d{6}", p.pincode)
    assert p.state and p.state != p.city


def test_synthetic_user_id_and_username_are_readable():
    p = build_victim_profile()
    assert p.first_name.lower() in p.user_id
    assert p.first_name.lower() in p.username


def test_synthetic_password_satisfies_a_normal_policy():
    """Upper, lower, digit and symbol, so a policy cannot reject it outright."""
    pw = build_victim_profile().password
    assert len(pw) >= 8
    assert any(c.isupper() for c in pw)
    assert any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(not c.isalnum() for c in pw)


def test_synthetic_mpin_is_four_digits():
    p = build_victim_profile()
    assert re.fullmatch(r"\d{4}", p.mpin)
    assert re.fullmatch(r"\d{4}", p.pin)


# ─── The profile is not a fingerprint ────────────────────────────────────────

def test_two_runs_do_not_present_the_same_identity():
    """
    A fixed identity is a one-string-compare sandbox tell.

    Drawn from a roster with a per-run salt, so every instance is a plausible
    person and no instance is always the same person.
    """
    seen = {build_victim_profile().username for _ in range(25)}
    assert len(seen) > 1


def test_deterministic_mode_pins_the_identity_for_a_reproducible_run(monkeypatch):
    monkeypatch.setenv("SUDARSHAN_VICTIM_DETERMINISTIC", "1")
    first = build_victim_profile()
    assert first == build_victim_profile()


# ─── The profile is configurable (§P8) ───────────────────────────────────────

def test_an_environment_override_wins():
    os.environ["SUDARSHAN_VICTIM_CITY"] = "Nashik"
    try:
        assert build_victim_profile().city == "Nashik"
    finally:
        del os.environ["SUDARSHAN_VICTIM_CITY"]


def test_a_malformed_profile_file_degrades_to_the_builtin_identity(tmp_path, monkeypatch):
    """An operator's typo must never be able to abort a run."""
    bad = tmp_path / "profile.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("SUDARSHAN_VICTIM_PROFILE_FILE", str(bad))
    assert build_victim_profile().city


def test_a_profile_file_is_applied(tmp_path, monkeypatch):
    good = tmp_path / "profile.json"
    good.write_text('{"city": "Indore", "state": "Madhya Pradesh"}', encoding="utf-8")
    monkeypatch.setenv("SUDARSHAN_VICTIM_PROFILE_FILE", str(good))
    p = build_victim_profile()
    assert (p.city, p.state) == ("Indore", "Madhya Pradesh")


# ─── Field values come from the profile ──────────────────────────────────────

@pytest.mark.parametrize("field_type,attribute", [
    (FieldType.FULL_NAME,  "full_name"),
    (FieldType.FIRST_NAME, "first_name"),
    (FieldType.LAST_NAME,  "last_name"),
    (FieldType.EMAIL,      "email"),
    (FieldType.PHONE,      "phone"),
    (FieldType.PHONE,     "phone"),
    (FieldType.USER_ID,    "user_id"),
    (FieldType.USERNAME,   "username"),
    (FieldType.PASSWORD,   "password"),
    (FieldType.MPIN,       "mpin"),
    (FieldType.CITY,       "city"),
    (FieldType.STATE,      "state"),
    (FieldType.ADDRESS,    "address"),
])
def test_the_profile_supplies_the_fields_it_owns(field_type, attribute):
    p = build_victim_profile()
    assert _value(field_type, p) == getattr(p, attribute)


def test_no_random_value_for_a_normal_semantic_field():
    """
    §P8: no meaningless strings where the field has a meaning.

    The exact failure this replaces: a "Full Name" box receiving
    ``Analysis Kqmz`` and a city box receiving ``Testville``.
    """
    p = build_victim_profile()
    assert "Analysis " not in _value(FieldType.FULL_NAME, p)
    assert _value(FieldType.CITY, p) != "Testville"
    assert _value(FieldType.STATE, p) != "Testland"


def test_a_profile_value_that_cannot_fit_the_field_is_refused_not_mangled():
    """
    Padding "Pune" to a declared 8-character minimum yields "Punexqvz",
    which is neither the profile's city nor a plausible one. Falling through
    to the generator produces a value built for that shape instead.
    """
    p = build_victim_profile()
    assert _value(FieldType.CITY, p, min_length=20) != p.city


def test_a_numeric_only_box_never_receives_letters():
    p = build_victim_profile()
    value = _value(FieldType.USER_ID, p, numeric_only=True)
    assert value.isdigit(), value


def test_an_exact_length_mpin_box_is_honoured():
    p = build_victim_profile()
    assert len(_value(FieldType.MPIN, p, min_length=6, max_length=6)) == 6


# ─── Declared attributes outrank an inferred caption ─────────────────────────

#: The live e-challan form, exactly as uiautomator dumps it. Every field's
#: caption renders INSIDE the field, so the "nearest preceding text node"
#: inference is off by one and each field inherits the PREVIOUS field's label.
_ECHALLAN_FORM = [
    ("After getting challan details you can further go for online payment",
     "Full Name*", "fullName", FieldType.FULL_NAME),
    ("Full Name*",     "Mobile Number*", "mb",  FieldType.PHONE),
    # MOTHER_NAME, not FULL_NAME: the parent-name patterns now lead the person
    # family, so this box no longer collapses into the applicant's own name
    # (and no longer receives the identical value). The point of the row is
    # unchanged - the field's own hint beats the neighbouring "Mobile Number*"
    # caption - and is now made more sharply.
    ("Mobile Number*", "Mother Name*",   "mt",  FieldType.MOTHER_NAME),
    ("Mobile Number*", "Date Of Birth*", "dob", FieldType.DATE_OF_BIRTH),
]


@pytest.mark.parametrize("label,hint,resource_id,expected", _ECHALLAN_FORM)
def test_a_fields_own_hint_outranks_a_neighbours_caption(
    label, hint, resource_id, expected,
):
    """
    A field is what its own attributes say it is.

    The "Mother Name" box carries hint="Mother Name*" and resource-id="mt",
    while the caption inferred for it is the previous field's "Mobile Number*".
    Everything used to be concatenated into one blob, so both matched and
    pattern order decided: the box was classified MOBILE and received a phone
    number. The form could never validate, "Get Details" never advanced, and
    the run reported no runtime behaviour at all.
    """
    from sudarshan_core.engines.agentic.credentials import (
        resolve_field_classification,
    )

    result = resolve_field_classification(
        field_label=label, hint=hint, resource_id=resource_id,
        class_name="android.widget.EditText",
    )
    assert result.field_type is expected, (
        f"{hint!r} (res={resource_id!r}) classified as "
        f"{result.field_type.value} from neighbour caption {label!r}"
    )


def test_a_caption_is_still_used_when_the_field_declares_nothing():
    """
    The inference is not discarded, only demoted.

    On the WebView banking corpus a field has no hint, no resource-id and no
    content-desc, so the caption rendered above it is the only human-readable
    name it has - and there the inference is right.
    """
    from sudarshan_core.engines.agentic.credentials import (
        resolve_field_classification,
    )

    result = resolve_field_classification(
        field_label="Login Password", class_name="android.widget.EditText",
    )
    assert result.field_type is FieldType.PASSWORD


def test_the_echallan_form_receives_the_right_value_in_every_box():
    """End to end: the four boxes of the real form, and what each gets."""
    from sudarshan_core.engines.agentic.credentials import (
        resolve_field_classification,
    )
    from sudarshan_core.engines.agentic.field_constraints import (
        extract_constraints,
    )

    p = build_victim_profile()
    values = {}
    for label, hint, resource_id, _ in _ECHALLAN_FORM:
        c = resolve_field_classification(
            field_label=label, hint=hint, resource_id=resource_id,
            class_name="android.widget.EditText",
        )
        constraints = extract_constraints(
            field_type=c.field_type, field_label=label, hint=hint,
            resource_id=resource_id, class_name="android.widget.EditText",
        )
        values[hint] = generate_value(constraints, profile=p)

    assert values["Full Name*"] == p.full_name
    assert values["Mobile Number*"] == p.phone
    # A mother's name is a NAME. The taxonomy has no MOTHER_NAME, so it shares
    # the person's; what matters is that it is not a phone number.
    assert not values["Mother Name*"].isdigit()
    assert re.fullmatch(r"\d{2}/\d{2}/\d{4}", values["Date Of Birth*"])


# ─── Vault integration ───────────────────────────────────────────────────────

def test_the_first_identity_a_vault_offers_comes_from_the_profile():
    vault = CredentialVault()
    assert vault.profile is not None
    assert vault.values["email"] == vault.profile.email
    assert vault.values["name"] == vault.profile.full_name


def test_rotation_drops_the_profile_so_a_retry_is_a_different_person():
    """
    §P8 gives the run a coherent identity; the retry ladder exists to find out
    whether the app rejects THAT identity or every identity. Reusing the
    profile after rotation would make every attempt look the same.
    """
    vault = CredentialVault()
    first = vault.values["username"]
    vault.regenerate()
    assert vault.profile is None
    assert vault.values["username"] != first


def test_no_plaintext_sensitive_values_escape_redaction():
    """§P28: every value the victim can type is redactable."""
    vault = CredentialVault()
    secrets = all_secret_values()
    for key in ("password", "otp", "email", "phone", "username"):
        assert vault.values[key] in secrets, key


# ─── Parent names ────────────────────────────────────────────────────────────
#
# Indian KYC and challan/RTO forms ask for a parent's name next to the
# applicant's. Both contain the word "name", so before MOTHER_NAME/FATHER_NAME
# existed the parent box classified as FULL_NAME - and because the vault caches
# one value per (type, length) it then received the IDENTICAL string as the
# applicant box. A form naming the applicant as their own mother fails exactly
# the cross-field check the question exists to make.

@pytest.mark.parametrize("hint,expected", [
    ("Mother Name*",       FieldType.MOTHER_NAME),
    ("Mother's Name",      FieldType.MOTHER_NAME),
    ("Mothers Name",       FieldType.MOTHER_NAME),
    ("MOTHER NAME",        FieldType.MOTHER_NAME),
    ("Mother's Full Name", FieldType.MOTHER_NAME),
    ("Father Name",        FieldType.FATHER_NAME),
    ("Father's Name",      FieldType.FATHER_NAME),
    ("Parent's Name",      FieldType.FATHER_NAME),
    ("Guardian's Name",    FieldType.GUARDIAN_NAME),
])
def test_a_parent_name_field_is_classified_as_a_parent_name(hint, expected):
    from sudarshan_core.engines.agentic.credentials import resolve_field_classification

    result = resolve_field_classification(
        field_label="", hint=hint, resource_id="", content_desc="",
        class_name="android.widget.EditText", text="", input_type="",
        is_password=False, index=1, screen_type="",
    )
    assert result.field_type is expected


def test_a_maiden_name_question_stays_a_security_answer():
    """
    "Mother's maiden name" is knowledge-based auth, not a demographic field.
    The parent patterns must not swallow it - SECURITY_ANSWER leads them.
    """
    from sudarshan_core.engines.agentic.credentials import resolve_field_classification

    result = resolve_field_classification(
        field_label="", hint="Mother's maiden name", resource_id="",
        content_desc="", class_name="android.widget.EditText", text="",
        input_type="", is_password=False, index=1, screen_type="",
    )
    assert result.field_type is FieldType.MOTHER_MAIDEN_NAME


def test_the_applicant_is_not_named_as_their_own_parent():
    """The whole point: three name boxes on one form get three names."""
    p = build_victim_profile()
    assert p.mother_name != p.full_name
    assert p.father_name != p.full_name
    assert p.mother_name != p.father_name


def test_a_parent_shares_the_family_surname():
    """
    Different person, same family. A parent's name that shares no surname with
    the applicant is as suspicious to a validator as an identical one.
    """
    p = build_victim_profile()
    assert p.mother_name.endswith(p.last_name)
    assert p.father_name.endswith(p.last_name)


def test_the_echallan_form_receives_four_distinct_values():
    """
    End to end over the live form's four fields: classify each, then draw its
    value from ONE vault, and assert the form is internally coherent.
    """
    from sudarshan_core.engines.agentic.credentials import (
        CredentialVault,
        resolve_field_classification,
    )
    from sudarshan_core.engines.agentic.field_constraints import extract_constraints

    vault = CredentialVault()
    filled = {}
    for hint, rid in [
        ("Full Name*", "fullName"), ("Mobile Number*", "mb"),
        ("Mother Name*", "mt"), ("Date Of Birth*", "dob"),
    ]:
        c = resolve_field_classification(
            field_label="", hint=hint, resource_id=rid, content_desc="",
            class_name="android.widget.EditText", text="", input_type="",
            is_password=False, index=0, screen_type="",
        )
        constraints = extract_constraints(
            field_type=c.field_type, field_label="", hint=hint, resource_id=rid,
            content_desc="", class_name="android.widget.EditText", text="",
            is_password=False, max_length=None, input_type="",
        )
        filled[c.field_type] = vault.value_for_field(constraints)

    assert set(filled) == {
        FieldType.FULL_NAME, FieldType.PHONE,
        FieldType.MOTHER_NAME, FieldType.DATE_OF_BIRTH,
    }
    assert filled[FieldType.FULL_NAME] != filled[FieldType.MOTHER_NAME]
    assert filled[FieldType.PHONE].isdigit()
    assert len(filled[FieldType.PHONE]) == 10
