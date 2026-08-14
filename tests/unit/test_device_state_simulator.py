"""Persona seeding: JSON templates -> content-provider inserts, no device needed.

The provider is faked so these run on any machine. What is actually under test
is the part that has to be right before a device is involved: deterministic
expansion, correct device-shell quoting, and honest reporting when a provider
refuses the write.
"""

from typing import List, Tuple

import pytest

from sudarshan_core.engines.device_state_simulator import (
    DeviceStateSimulator,
    _solid_png,
    sh_quote,
)
from sudarshan_core.engines.persona import (
    Persona,
    SmsMessage,
    list_personas,
    load_persona,
)


class FakeProvider:
    """Records shell commands instead of touching a device."""

    def __init__(self, refuse: List[str] = None, rooted: bool = True, api: int = 33):
        self.commands: List[str] = []
        self.refuse = refuse or []
        self.rooted = rooted
        self.api = api

    def adb_shell(self, serial: str, command: str, timeout: int = 30) -> Tuple[bool, str]:
        self.commands.append(command)
        if command.startswith("getprop ro.build.version.sdk"):
            return True, str(self.api)
        if any(marker in command for marker in self.refuse):
            return False, "java.lang.SecurityException: Permission Denial"
        if "content query" in command:
            return True, "\n".join(f"Row: {i} _id={i + 1}" for i in range(12))
        return True, "__OK__\n" * command.count("__OK__")

    def check_root(self, serial: str) -> bool:
        return self.rooted


@pytest.fixture
def simulator():
    provider = FakeProvider()
    return DeviceStateSimulator("emulator-5554", provider=provider), provider


# ── Templates ──────────────────────────────────────────────────────────────


def test_shipped_templates_are_discoverable():
    personas = {p["persona_id"] for p in list_personas()}
    assert "default_retail_user" in personas
    assert "minimal_privacy_user" in personas


def test_expansion_is_deterministic():
    """A re-run for verification must produce the same device state."""
    a = load_persona("default_retail_user", now_ms=1_760_000_000_000)
    b = load_persona("default_retail_user", now_ms=1_760_000_000_000)
    assert [c.phone for c in a.contacts] == [c.phone for c in b.contacts]
    assert [c.number for c in a.calls] == [c.number for c in b.calls]


def test_expansion_produces_a_plausible_address_book():
    persona = load_persona("default_retail_user", now_ms=1_760_000_000_000)
    assert len(persona.contacts) == 120
    # Duplicate numbers would be visible to a sample profiling the device.
    assert len({c.phone for c in persona.contacts}) == len(persona.contacts)
    assert all(c.display_name.strip() for c in persona.contacts)


def test_bank_alert_messages_are_present():
    persona = load_persona("default_retail_user", now_ms=1_760_000_000_000)
    blob = " ".join(m.body for m in persona.messages).lower()
    assert "otp" in blob
    assert any("debited" in m.body.lower() or "credited" in m.body.lower() for m in persona.messages)


def test_messages_are_backdated_not_all_now():
    now = 1_760_000_000_000
    persona = load_persona("default_retail_user", now_ms=now)
    assert all(m.timestamp_ms < now for m in persona.messages)


def test_unknown_persona_returns_none():
    assert load_persona("no_such_persona") is None


# ── Shell quoting ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw",
    ["plain", "has space", "it's", "a;b && rm -rf /", "OTP 123, valid", '"quoted"', "$(id)"],
)
def test_values_are_quoted_for_the_device_shell(raw):
    quoted = sh_quote(raw)
    assert quoted.startswith("'") and quoted.endswith("'")
    # POSIX single-quote escaping: the only way a quote can appear is as '\''
    assert "'" not in quoted[1:-1].replace("'\\''", "")


def test_metacharacters_in_a_template_cannot_break_out(simulator):
    """Templates are operator-editable, so their content is not trusted input.

    The property that matters is what the *device's shell* does with the
    command, so it is verified by parsing the command the way that shell would
    (`shlex` in POSIX mode) and checking the hostile text comes back as a
    single argument rather than as extra words the shell would execute.
    """
    import shlex

    sim, provider = simulator
    hostile_body = "x'; rm -rf /; echo '"
    hostile_address = "A; reboot"
    persona = Persona(
        persona_id="hostile",
        display_name="hostile",
        messages=[
            SmsMessage(address=hostile_address, body=hostile_body, timestamp_ms=1)
        ],
    )
    sim.seed_persona("hostile", persona=persona, include=["messages"])

    inserts = [c for c in provider.commands if "content insert" in c]
    assert inserts
    for command in inserts:
        tokens = shlex.split(command, posix=True)
        # Survives intact as ONE token, carried as data...
        assert f"body:s:{hostile_body}" in tokens
        assert f"address:s:{hostile_address}" in tokens
        # ...and never becomes a command the shell would run.
        assert "rm" not in tokens
        assert "reboot" not in tokens


# ── Seeding ────────────────────────────────────────────────────────────────


def test_seeding_writes_to_every_provider(simulator):
    sim, provider = simulator
    result = sim.seed_persona("minimal_privacy_user")
    assert result.ok
    assert result.contacts_inserted > 0
    assert result.messages_inserted > 0
    assert result.calls_inserted > 0
    assert result.photos_pushed > 0

    joined = " ".join(provider.commands)
    assert "content://com.android.contacts/raw_contacts" in joined
    assert "content://sms/inbox" in joined
    assert "content://call_log/calls" in joined


def test_sms_refusal_is_reported_not_hidden():
    """Android blocks shell SMS writes from API 29; partial success is normal."""
    provider = FakeProvider(refuse=["content://sms"])
    result = DeviceStateSimulator("x", provider=provider).seed_persona("minimal_privacy_user")
    assert result.ok, "other providers still succeeded"
    assert result.messages_inserted == 0
    assert any("SMS provider refused" in w for w in result.warnings)


def test_total_refusal_reports_an_error():
    provider = FakeProvider(refuse=["content insert", "base64"])
    result = DeviceStateSimulator("x", provider=provider).seed_persona("minimal_privacy_user")
    assert result.ok is False
    assert result.errors


def test_non_root_device_warns_but_still_attempts():
    provider = FakeProvider(rooted=False)
    result = DeviceStateSimulator("x", provider=provider).seed_persona("minimal_privacy_user")
    assert result.rooted is False
    assert any("not root" in w for w in result.warnings)


def test_unknown_persona_is_an_error_not_a_silent_no_op():
    result = DeviceStateSimulator("x", provider=FakeProvider()).seed_persona("nope")
    assert result.ok is False
    assert result.errors


def test_include_filter_limits_the_providers_touched(simulator):
    sim, provider = simulator
    result = sim.seed_persona("minimal_privacy_user", include=["contacts"])
    assert result.contacts_inserted > 0
    assert result.messages_inserted == 0
    assert "content://sms" not in " ".join(provider.commands)


def test_api_level_is_probed_from_the_device():
    provider = FakeProvider(api=29)
    result = DeviceStateSimulator("x", provider=provider).seed_persona("minimal_privacy_user")
    assert result.api_level == 29


# ── Placeholder images ─────────────────────────────────────────────────────


def test_generated_png_is_spec_valid():
    import struct

    png = _solid_png(64, 48, (52, 73, 94))
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert png[12:16] == b"IHDR"
    assert struct.unpack(">II", png[16:24]) == (64, 48)
    assert png[-8:-4] == b"IEND"
