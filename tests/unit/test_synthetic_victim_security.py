"""
SUDARSHAN - Synthetic victim: credential containment and leak audit.

The synthetic-victim work put credential VALUES on more paths than before -
constraint-aware generation, a second classifier, a model escalation - and each
of those is a place a value could escape. These are the tests that say it does
not.

The specific defect these were written against: `ui_explorer.py` shipped its own
`FORM_VALUES` table with different values from the agentic executor's. The audit
log redacts `credentials.all_secret_values()` plus the AGENTIC table, so nothing
the legacy explorer typed was ever redacted - and `frida_sandbox` keeps that
explorer as its rollback path, so it was live. There must be ONE authoritative
synthetic credential source, and everything typeable must be redactable.
"""

from __future__ import annotations

import asyncio
import io
import sys
import tokenize
from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.audit_log import AuditLog  # noqa: E402
from sudarshan_core.engines.agentic.credentials import (  # noqa: E402
    CredentialVault,
    all_secret_values,
    get_vault,
    login_rejected,
    login_succeeded_hint,
)


# ─── One authoritative credential source ─────────────────────────────────────

_UI_EXPLORER_PATH = (
    _ROOT / "shared" / "sudarshan_core" / "engines" / "ui_explorer.py"
)


def _code_without_comments(path: Path) -> str:
    """
    The file's executable text, with comments and docstrings removed.

    Scanning raw source for a leaked literal would also match the comment that
    explains why the literal was removed, so these checks would pass or fail
    on prose. Tokenising first means they assert on code.
    """
    source = path.read_text(encoding="utf-8")
    out: list[str] = []
    prev_type = None
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            continue
        # A string that opens a logical line is a docstring, not a value.
        if (
            tok.type == tokenize.STRING
            and prev_type in (tokenize.INDENT, tokenize.NEWLINE, tokenize.NL, None)
        ):
            prev_type = tok.type
            continue
        out.append(tok.string)
        prev_type = tok.type
    # Whitespace-collapsed so a caller can match a phrase without having to
    # reproduce the tokeniser's spacing.
    return " ".join(" ".join(out).split())


def test_the_legacy_explorer_no_longer_owns_a_credential_table():
    """
    UIExplorer must not define its own values.

    It is not dead code - frida_sandbox keeps it as the rollback explorer - so
    a private table there is a live unredacted credential path.

    Asserted on the module's code rather than by importing it: ui_explorer
    imports google.genai at module scope, which is not installed in every
    environment the unit suite runs in.
    """
    code = _code_without_comments(_UI_EXPLORER_PATH).replace(" ", "")
    assert "fromsudarshan_core.engines.agentic.tool_executorimportFORM_VALUES" in code
    # No local dict literal reassigning the shared name.
    assert "FORM_VALUES={" not in code


def test_the_removed_legacy_values_are_gone_from_the_code():
    """The specific strings that used to be typed unredacted."""
    code = _code_without_comments(_UI_EXPLORER_PATH)
    for leaked in ("Password@123", "demo@gmail.com", "9876543210", "Test User"):
        assert leaked not in code, leaked


def test_the_legacy_explorer_shares_the_authoritative_table_when_importable():
    """The stronger identity check, where the optional dependency is present."""
    pytest.importorskip("google.genai")
    from sudarshan_core.engines import ui_explorer
    from sudarshan_core.engines.agentic import tool_executor

    assert ui_explorer.FORM_VALUES is tool_executor.FORM_VALUES


def test_every_static_form_value_is_redactable():
    """A value that can be typed must be a value that can be redacted."""
    from sudarshan_core.engines.agentic import tool_executor

    assert set(tool_executor.FORM_VALUES.values()) <= all_secret_values()


def test_vault_values_are_redactable():
    vault = get_vault("com.example.test")
    assert set(vault.values.values()) <= all_secret_values()


def test_regenerated_credentials_stay_redactable():
    """
    A password issued before a regeneration must still be redacted afterwards,
    or a log line written earlier is retroactively exposed.
    """
    vault = get_vault("com.example.regen")
    old = set(vault.values.values())
    vault.regenerate()
    assert old <= all_secret_values()


# ─── Redaction ───────────────────────────────────────────────────────────────

def test_audit_log_redacts_a_credential_value_in_an_action():
    from sudarshan_core.engines.agentic import tool_executor

    secret = tool_executor.FORM_VALUES["password"]
    safe = AuditLog._sanitize_action({"tool": "type_text", "text": secret})
    assert safe["text"] == "[REDACTED_CREDENTIAL_VALUE]"
    assert secret not in str(safe)


def test_audit_log_redacts_a_constraint_generated_value():
    """The new generation path must be behind the same choke point."""
    from sudarshan_core.engines.agentic.field_constraints import extract_constraints
    from sudarshan_core.engines.agentic.field_taxonomy import FieldType

    vault = get_vault("com.example.redact")
    value = vault.value_for_field(
        extract_constraints(field_type=FieldType.MPIN, field_label="MPIN")
    )
    safe = AuditLog._sanitize_action({"tool": "type_text", "text": value})
    assert safe["text"] == "[REDACTED_CREDENTIAL_VALUE]"


def test_field_hint_itself_is_not_redacted():
    """Redacting the hint would destroy the record of WHICH field was filled."""
    safe = AuditLog._sanitize_action(
        {"tool": "type_text", "field_hint": "password", "text": "password"}
    )
    assert safe["field_hint"] == "password"


# ─── ToolResult must not carry values ────────────────────────────────────────

def _executor_with_mock_adb(package_name: str):
    """A ToolExecutor whose ADB channel is canned, per the suite's convention."""
    from unittest.mock import AsyncMock

    from sudarshan_core.engines.agentic.tool_executor import ToolExecutor

    executor = ToolExecutor(
        device_serial="emulator-5554", package_name=package_name,
    )
    executor._adb = AsyncMock(return_value=(True, ""))
    return executor


def test_type_text_result_never_contains_the_typed_value():
    """
    Only the field's identity and the LENGTH of what was typed come back.

    The length is needed to detect silent truncation and leaks nothing: it is
    already implied by the field's own on-screen constraints.
    """
    executor = _executor_with_mock_adb("com.example.leak")

    result = asyncio.run(executor.execute({
        "tool": "type_text", "field_hint": "password",
        "field_type": "MPIN", "field_min_length": 4, "field_max_length": 4,
        "field_numeric_only": True, "x": 10, "y": 10,
    }))

    assert result.success
    vault = get_vault("com.example.leak")
    blob = str(result.data) + str(result.output or "")
    for secret in vault.secrets():
        assert secret not in blob, "a credential value reached ToolResult"
    assert result.data["field_hint"] == "password"
    assert result.data["typed_length"] == 4


def test_constraint_aware_typing_sizes_the_value_to_the_field():
    """End of the chain: a 4-digit MPIN field receives exactly 4 digits."""
    executor = _executor_with_mock_adb("com.example.mpin")

    asyncio.run(executor.execute({
        "tool": "type_text", "field_hint": "password", "field_type": "MPIN",
        "field_min_length": 4, "field_max_length": 4, "field_numeric_only": True,
        "x": 10, "y": 10,
    }))

    typed = [
        c.args[-1] for c in executor._adb.await_args_list
        if len(c.args) > 2 and c.args[1] == "input" and c.args[2] == "text"
    ]
    assert typed, "nothing was typed"
    value = typed[-1].strip("'\"")
    assert len(value) == 4 and value.isdigit(), value


def test_a_legacy_action_without_a_field_type_still_works():
    """Backward compatibility: field_hint alone must keep working."""
    executor = _executor_with_mock_adb("com.example.legacy")
    result = asyncio.run(executor.execute({
        "tool": "type_text", "field_hint": "username", "x": 5, "y": 5,
    }))
    assert result.success
    assert result.data["field_hint"] == "username"


# ─── The legacy explorer's model-supplied text path ──────────────────────────

def test_unknown_model_key_is_not_typed_verbatim():
    """
    `FORM_VALUES.get(key, key)` used to type the model's own string when the
    key was unrecognised, letting attacker-influenced screen content reach
    `adb shell input text` unbounded. An unknown key must be a miss.
    """
    code = _code_without_comments(_UI_EXPLORER_PATH)
    assert "FORM_VALUES.get(dict_key,dict_key)" not in code.replace(" ", "")
    # The replacement resolves through the vault and falls back to a known key.
    assert "get_vault" in code


# ─── Outcome detection (unchanged behaviour) ─────────────────────────────────

@pytest.mark.parametrize("text", [
    "Invalid credentials", "Login failed", "Incorrect password",
    "User not found", "Authentication failed",
])
def test_rejection_phrases_still_detected(text):
    assert login_rejected(text)


def test_silence_is_not_a_rejection():
    assert not login_rejected("")
    assert not login_rejected("Please wait...")


@pytest.mark.parametrize("text", [
    "Log Out", "Account Summary", "Available Balance", "Fund Transfer",
])
def test_success_landmarks_still_detected(text):
    assert login_succeeded_hint(text)


# ─── Values are synthetic ────────────────────────────────────────────────────

def test_no_generated_identity_resolves_to_a_real_service():
    vault = CredentialVault()
    assert vault.values["email"].endswith("@sudarshan-analysis.test")
    assert vault.values["host"] == "127.0.0.1"


def test_two_runs_never_present_the_same_identity():
    """A sample must not be able to fingerprint the analysis by its credentials."""
    first = CredentialVault().values["username"]
    seen = {CredentialVault().values["username"] for _ in range(8)}
    assert seen != {first}
