"""
The victim half of the engine: following a multi-stage journey to its end.

The regression these cover is a run that stopped one tap into a dropper. The
sample raised the VpnService consent dialog, the explorer read
com.android.vpndialogs as an unrelated third-party app, recorded the [INSTALL]
button that led there as an "escaping action", and from then on refused to
press INSTALL on that screen again. The second stage was never reached, and the
report said the sample did nothing.

Three separate faults produced that one outcome, and each is pinned here:

  * com.android.vpndialogs matched no branch of classify_safe_boundary();
  * a safe boundary crossing was blamed on the control that caused it;
  * the payload path regex matched only *.apk, so un2vis.zip - the archive that
    actually carried the second stage - was never preserved or opened.
"""

from __future__ import annotations

import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.perception import (  # noqa: E402
    in_investigation_scope,
)
from sudarshan_core.engines.agentic.screen_classifier import (  # noqa: E402
    ScreenType,
    classify_screen,
    classify_screen_with_ownership,
)
from sudarshan_core.engines.agentic.screenshot_policy import (  # noqa: E402
    SafeInteractiveBoundaryRole,
    ScreenOwnership,
    classify_safe_boundary,
    is_safe_interactive_boundary,
    resolve_screen_ownership,
)
from sudarshan_core.engines.agentic.secondary_payload import (  # noqa: E402
    SecondaryPayload,
    SecondaryPayloadTracker,
    extract_and_catalog_archive,
    extract_apk_path,
    sha256_file,
)
from sudarshan_core.engines.agentic.victim_policy import (  # noqa: E402
    VICTIM_REJECT_THRESHOLD,
    is_victim_rejected,
    rank_action_candidates,
    score_ui_node,
)

TARGET = "com.evil.dropper"
VPN_DIALOGS = "com.android.vpndialogs"


@dataclass
class _Node:
    """Enough of a UINode for the classifiers and the victim policy."""

    text: str = ""
    desc: str = ""
    resource_id: str = ""
    class_name: str = "android.widget.Button"
    is_input: bool = False
    center_x: int = 100
    center_y: int = 200


def _btn(label: str) -> _Node:
    return _Node(text=label)


# ── 1. Victim scoring ─────────────────────────────────────────────────────────

def test_allow_outranks_deny():
    assert score_ui_node("ALLOW", "", "", "android.widget.Button") > score_ui_node(
        "DENY", "", "", "android.widget.Button"
    )


def test_install_outranks_cancel():
    assert score_ui_node("INSTALL", "", "", "android.widget.Button") > score_ui_node(
        "CANCEL", "", "", "android.widget.Button"
    )


@pytest.mark.parametrize("label", ["Do not allow", "Don't allow", "DON'T ALLOW"])
def test_a_refusal_containing_allow_is_penalised_not_rewarded(label):
    """
    The bug this pins: substring matching read "Don't allow" as "allow" and the
    simulated victim denied the very permission it was there to grant.
    """
    score = score_ui_node(label, "", "", "android.widget.Button")
    assert score < 0
    assert is_victim_rejected(score)


@pytest.mark.parametrize("label", [
    "ALLOW", "Always allow", "While using the app", "INSTALL",
    "Install anyway", "UPDATE NOW", "Allow from this source",
    "Enable service", "OK", "Continue",
])
def test_permissive_controls_are_all_positively_scored(label):
    assert score_ui_node(label, "", "", "android.widget.Button") > 0


@pytest.mark.parametrize("label", [
    "DENY", "CANCEL", "Not now", "Skip", "Dismiss", "Close app",
    "Uninstall", "Block", "Remind me later",
])
def test_declining_controls_are_all_rejected(label):
    assert is_victim_rejected(score_ui_node(label, "", "", "android.widget.Button"))


def test_a_boundary_screen_raises_the_affirmative_control():
    """Saying yes on a consent prompt is worth more than saying yes elsewhere."""
    plain = score_ui_node("Allow", "", "", "android.widget.Button", "")
    boundary = score_ui_node(
        "Allow", "", "", "android.widget.Button", "SYSTEM_PERMISSION"
    )
    assert boundary > plain


def test_ranking_puts_the_permissive_control_first():
    nodes = [_btn("Cancel"), _btn("Do not allow"), _btn("Allow"), _btn("Later")]
    ranked = rank_action_candidates(nodes, "SYSTEM_PERMISSION")
    assert ranked[0][0].text == "Allow"
    assert all(is_victim_rejected(v) for _, v in ranked[1:])


def test_ranking_is_deterministic():
    """Two runs over the same hierarchy must produce the same walk."""
    nodes = [_btn("Cancel"), _btn("Install"), _btn("Update"), _btn("Help")]
    first = [n.text for n, _ in rank_action_candidates(list(nodes), "UPDATE_PROMPT")]
    second = [n.text for n, _ in rank_action_candidates(list(nodes), "UPDATE_PROMPT")]
    assert first == second


def test_an_unlabelled_control_is_scored_by_its_class_not_dropped():
    assert score_ui_node("", "", "", "android.widget.Switch") > 0
    assert score_ui_node("", "", "", "") == 0


# ── 2. Boundary classification ────────────────────────────────────────────────

def test_the_vpn_consent_dialog_is_a_safe_boundary():
    """
    Root cause #1. This returned NONE: vpndialogs is not Settings, not an
    installer, and has no "permission" in its name, so it fell through every
    branch and the explorer treated a prompt the SAMPLE raised as a foreign app.
    """
    role = classify_safe_boundary(VPN_DIALOGS, VPN_DIALOGS + "/.ConfirmDialog")
    assert role == SafeInteractiveBoundaryRole.VPN_DIALOG
    assert is_safe_interactive_boundary(VPN_DIALOGS, VPN_DIALOGS + "/.ConfirmDialog")


def test_the_vpn_consent_dialog_is_owned_as_a_system_permission():
    assert resolve_screen_ownership(VPN_DIALOGS, TARGET) == (
        ScreenOwnership.SYSTEM_PERMISSION
    )


def test_the_vpn_consent_dialog_is_in_investigation_scope():
    assert in_investigation_scope(VPN_DIALOGS, TARGET) is True


@pytest.mark.parametrize("pkg", [
    "com.samsung.android.packageinstaller",
    "com.miui.packageinstaller",
    "com.transsion.installer",
])
def test_oem_installers_classify_as_installers(pkg):
    assert classify_safe_boundary(pkg, pkg + "/.InstallStart") == (
        SafeInteractiveBoundaryRole.SYSTEM_INSTALLER
    )
    assert resolve_screen_ownership(pkg, TARGET) == ScreenOwnership.SYSTEM_INSTALLER
    assert in_investigation_scope(pkg, TARGET) is True


@pytest.mark.parametrize("pkg", [
    "com.miui.securitycenter", "com.coloros.safecenter", "com.oppo.market",
])
def test_multi_purpose_oem_apps_are_in_scope_only_while_a_prompt_is_up(pkg):
    """
    Same rule as com.android.settings. These are whole applications; admitting
    them on package identity would let a run spend its entire budget in an OEM
    battery manager and never observe the sample.
    """
    assert in_investigation_scope(pkg, TARGET) is False
    assert in_investigation_scope(
        pkg, TARGET, screen_type="PACKAGE_INSTALLER"
    ) is True


def test_the_vpn_prompt_text_classifies_as_a_vpn_request():
    nodes = [
        _Node(text="Connection request"),
        _Node(
            text="Dropper wants to set up a VPN connection that allows it to "
                 "monitor network traffic. Only accept if you trust the source."
        ),
        _btn("Cancel"),
        _btn("OK"),
    ]
    classified = classify_screen(VPN_DIALOGS + "/.ConfirmDialog", nodes)
    assert classified.screen_type == ScreenType.VPN_REQUEST


def test_external_ownership_does_not_flatten_a_vpn_request_to_external_app():
    """
    Root cause #1b. Returning EXTERNAL_APP here hands the ExplorationGraph a
    type that is not interactive, so it builds no action inventory and the
    victim is never offered the OK button.
    """
    nodes = [
        _Node(text="Connection request"),
        _Node(text="wants to set up a VPN connection"),
        _btn("Cancel"),
        _btn("OK"),
    ]
    result = classify_screen_with_ownership(
        "com.unknown.oem.vpnhost/.Confirm", nodes, "", TARGET,
        foreground_package="com.unknown.oem.vpnhost",
    )
    assert result.screen_type == ScreenType.VPN_REQUEST
    assert result.screen_type != ScreenType.EXTERNAL_APP


def test_an_installer_with_unreadable_text_keeps_its_installer_identity():
    """Ownership knows what surface this is even when the text dump is empty."""
    result = classify_screen_with_ownership(
        "com.miui.packageinstaller/.InstallProgress", [], "", TARGET,
        foreground_package="com.miui.packageinstaller",
    )
    assert result.screen_type in (
        ScreenType.PACKAGE_INSTALLER, ScreenType.EXTERNAL_APK,
    )
    assert result.ownership == ScreenOwnership.SYSTEM_INSTALLER.value


@pytest.mark.parametrize("text", [
    "Do you want to install this application?",
    "Allow from this source",
    "Install unknown apps",
    "Install anyway",
    "Harmful app blocked",
])
def test_installer_phrasings_are_recognised(text):
    classified = classify_screen("com.example/.X", [_Node(text=text)])
    assert classified.screen_type in (
        ScreenType.EXTERNAL_APK, ScreenType.PACKAGE_INSTALLER,
    )


def test_an_unrelated_app_is_still_not_a_safe_boundary():
    """The widening must not make everything in scope."""
    assert is_safe_interactive_boundary(
        "com.android.contacts", "com.android.contacts/.Main"
    ) is False
    assert in_investigation_scope("com.android.contacts", TARGET) is False


def test_an_app_named_like_an_installer_does_not_get_in_on_its_name_alone():
    """A sample can name its own Activity anything; that is not evidence."""
    assert classify_safe_boundary(
        "com.evil.dropper", "com.evil.dropper/.PackageInstallerActivity"
    ) == SafeInteractiveBoundaryRole.NONE


# ── 3. Escaping-action safety ─────────────────────────────────────────────────

def _memory(screen_hash: str = "screen-install"):
    from sudarshan_core.engines.agentic.agent_memory import AgentMemory

    mem = AgentMemory()
    mem.current_screen_hash = screen_hash
    return mem


def test_a_crossing_into_the_vpn_dialog_is_not_an_escape():
    """
    Root cause #2. The guard asked is_safe_interactive_boundary() and got
    False for vpndialogs, so it recorded [INSTALL] as escaping and the button
    was blacklisted on that screen for the rest of the run.
    """
    assert is_safe_interactive_boundary(
        VPN_DIALOGS, VPN_DIALOGS + "/.ConfirmDialog"
    ) is True

    mem = _memory()
    # What the guard does when the destination IS a safe boundary: nothing.
    assert mem.is_escaping_action("click_text", "INSTALL") is False


def test_the_guard_consults_the_boundary_check_before_blaming_an_action():
    """Pins the ordering in the loop, which is where the bug actually lived."""
    import inspect

    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    source = inspect.getsource(AgenticExplorer.start)
    guard = source.index("fg_is_safe_boundary")
    blame = source.index("record_escaping_action")
    assert guard < blame, "the boundary check must precede the escape record"
    assert "BOUNDARY_TRANSITION" in source


def test_the_boundary_check_is_given_the_screen_text():
    """
    An OEM installer needs TWO signals, and the second is a marker in the UI
    text. Passing no text left every OEM installer one signal short.
    """
    import inspect

    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    source = inspect.getsource(AgenticExplorer.start)
    start = source.index("fg_is_safe_boundary")
    call = source[start:start + 200]
    assert "screen_text" in call


def test_a_genuine_escape_is_still_remembered():
    """The fix must not disarm the guard for real departures."""
    mem = _memory()
    assert is_safe_interactive_boundary("com.android.contacts", "") is False
    mem.record_escaping_action("click_text", "Phone")
    assert mem.is_escaping_action("click_text", "Phone") is True


def test_escaping_memory_is_scoped_to_the_screen_it_happened_on():
    mem = _memory("screen-a")
    mem.record_escaping_action("click_text", "Share")
    mem.current_screen_hash = "screen-b"
    assert mem.is_escaping_action("click_text", "Share") is False


def test_is_action_effective_answers_for_a_screen_the_walk_is_not_on():
    mem = _memory("screen-a")
    mem.record_escaping_action("click_text", "Share")
    mem.current_screen_hash = "screen-b"
    assert mem.is_action_effective("screen-a", "click_text", "Share") is False
    assert mem.is_action_effective("screen-b", "click_text", "Share") is True


def test_is_action_effective_gives_up_on_a_control_that_never_moves():
    from sudarshan_core.engines.agentic.agent_memory import MAX_ACTIONS_PER_SCREEN

    mem = _memory("screen-a")
    for _ in range(MAX_ACTIONS_PER_SCREEN):
        mem.record_action("click_text", "Retry", "GOAL", "why", success=True)
    assert mem.is_action_effective("screen-a", "click_text", "Retry") is False


# ── 4. Victim-weighted action selection ───────────────────────────────────────

def _action(label: str, action_id: str):
    from sudarshan_core.engines.agentic.exploration_engine import ActionItem

    return ActionItem(
        action_id=action_id, node_id=action_id, action_type="click", label=label,
    )


def test_the_prioritizer_ranks_install_above_cancel_on_an_installer_screen():
    from sudarshan_core.engines.agentic.exploration_engine import (
        ActionPrioritizer,
        ApplicationProfile,
    )

    actions = [
        _action("Cancel", "a1"),
        _action("Install", "a2"),
        _action("Do not allow", "a3"),
    ]
    ranked = ActionPrioritizer.rank_actions(
        actions, ApplicationProfile(), "PACKAGE_INSTALLER",
    )
    assert ranked[0].label == "Install"
    assert ranked[0].victim_score > 0
    assert all(a.victim_score < VICTIM_REJECT_THRESHOLD for a in ranked[1:])


def test_declining_actions_are_deferred_not_deleted():
    """
    A screen whose only remaining control is Cancel still has to be left, so
    the negatives come back once the affirmatives are gone.
    """
    import inspect

    from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph

    source = inspect.getsource(ExplorationGraph)
    assert "is_victim_rejected" in source
    assert "ranked = remaining + rejected" in source


# ── 5. Archive extraction and provenance ──────────────────────────────────────

def _make_un2vis_zip(path: Path) -> None:
    """The archive shape a real dropper ships: code, a nested APK, a native lib."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00" + b"A" * 64)
        zf.writestr("payload.apk", b"PK\x03\x04" + b"B" * 64)
        zf.writestr("lib/arm64-v8a/libcore.so", b"\x7fELF" + b"C" * 64)
        zf.writestr("assets/config.json", b'{"c2": "example.invalid"}')
        zf.writestr("res/icon.png", b"\x89PNG" + b"D" * 32)


@pytest.mark.parametrize("path", [
    "/sdcard/Download/un2vis.zip",
    "/data/data/com.evil.dropper/files/classes.dex",
    "/sdcard/payload.jar",
    "/data/local/tmp/libhook.so",
    "/sdcard/Download/update.apk",
])
def test_every_executable_payload_extension_is_detected(path):
    """
    Root cause #3. The regex matched only *.apk, so a dropper that shipped its
    second stage as un2vis.zip produced no payload record at all.
    """
    assert extract_apk_path({"path": path}) == path


def test_a_data_file_is_still_not_a_payload():
    """Widening the regex must not turn every file write into a finding."""
    assert extract_apk_path({"path": "/data/data/com.evil.app/files/cache.db"}) == ""
    assert extract_apk_path({"path": "/sdcard/Pictures/photo.png"}) == ""


def test_the_archive_is_unpacked_and_every_executable_child_is_hashed(tmp_path):
    archive = tmp_path / "un2vis.zip"
    _make_un2vis_zip(archive)
    parent_hash = sha256_file(archive)

    children = extract_and_catalog_archive(
        archive, tmp_path / "unpacked", parent_sha256=parent_hash,
    )

    names = {c["filename"] for c in children}
    assert names == {"classes.dex", "payload.apk", "lib/arm64-v8a/libcore.so"}
    assert {c["type"] for c in children} == {"DEX", "APK", "SO"}

    for child in children:
        assert len(child["sha256"]) == 64
        int(child["sha256"], 16)                      # real hex, not a placeholder
        assert child["parent_sha256"] == parent_hash  # provenance is recorded
        on_disk = Path(child["local_path"])
        assert on_disk.is_file()
        assert sha256_file(on_disk) == child["sha256"]


def test_non_executable_members_are_not_catalogued(tmp_path):
    archive = tmp_path / "un2vis.zip"
    _make_un2vis_zip(archive)
    children = extract_and_catalog_archive(archive, tmp_path / "unpacked")
    assert not any(c["filename"].endswith((".json", ".png")) for c in children)


def test_a_traversing_member_is_refused(tmp_path):
    """
    Zip Slip. The sample authored this archive, and a member named
    ../../evil.dex would otherwise write outside the artifact directory.
    """
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../../evil.dex", b"dex\n035\x00")
        zf.writestr("classes.dex", b"dex\n035\x00")

    out = tmp_path / "unpacked"
    children = extract_and_catalog_archive(archive, out)

    assert [c["filename"] for c in children] == ["classes.dex"]
    assert not (tmp_path.parent / "evil.dex").exists()
    assert not (tmp_path / "evil.dex").exists()
    for leaked in tmp_path.rglob("evil.dex"):
        pytest.fail("traversing member escaped to " + str(leaked))


def test_an_absolute_member_path_is_refused(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("/tmp/rooted.so", b"\x7fELF")
    assert extract_and_catalog_archive(archive, tmp_path / "unpacked") == []


def test_a_file_that_is_not_an_archive_yields_nothing(tmp_path):
    plain = tmp_path / "notes.zip"
    plain.write_bytes(b"this is not a zip")
    assert extract_and_catalog_archive(plain, tmp_path / "unpacked") == []


def test_a_missing_archive_yields_nothing(tmp_path):
    assert extract_and_catalog_archive(
        tmp_path / "absent.zip", tmp_path / "unpacked"
    ) == []


def test_the_extraction_budget_bounds_a_zip_bomb(tmp_path):
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge.dex", b"\x00" * (1 << 20))
    children = extract_and_catalog_archive(
        archive, tmp_path / "unpacked", max_total_bytes=1024,
    )
    assert children == []


def test_unpacking_records_the_children_against_the_parent_payload(tmp_path):
    """The chain "app wrote un2vis.zip, which held classes.dex" as one fact."""
    archive = tmp_path / "un2vis.zip"
    _make_un2vis_zip(archive)

    tracker = SecondaryPayloadTracker(parent_package=TARGET)
    payload = SecondaryPayload(
        device_path="/sdcard/Download/un2vis.zip",
        local_path=str(archive),
        sha256=sha256_file(archive),
    )
    tracker.unpack(payload, tmp_path)

    assert len(payload.child_artifacts) == 3
    assert all(c["parent_sha256"] == payload.sha256 for c in payload.child_artifacts)
    assert "child_artifacts" in payload.to_dict()


def test_a_preserved_apk_is_not_exploded_into_its_own_members(tmp_path):
    """identify() reads an APK's metadata; copying its dex tree adds no claim."""
    apk = tmp_path / "update.apk"
    _make_un2vis_zip(apk)

    payload = SecondaryPayload(device_path="/sdcard/update.apk", local_path=str(apk))
    SecondaryPayloadTracker().unpack(payload, tmp_path)
    assert payload.child_artifacts == []


def test_the_tracker_summary_reports_unpacked_archives(tmp_path):
    archive = tmp_path / "un2vis.zip"
    _make_un2vis_zip(archive)

    tracker = SecondaryPayloadTracker(parent_package=TARGET)
    payload = tracker.observe_event({
        "hook": "FileOutputStream.apkWrite",
        "path": "/sdcard/Download/un2vis.zip",
    })
    assert payload is not None
    payload.local_path = str(archive)
    payload.sha256 = sha256_file(archive)
    tracker.unpack(payload, tmp_path)

    summary = tracker.summary()
    assert summary["archives_unpacked"] == 1
    assert summary["child_artifacts"] == 3


# ── 6. Target process continuity ──────────────────────────────────────────────

def _explorer():
    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    return AgenticExplorer(device_serial="test-device", package_name=TARGET)


def test_a_pid_change_is_recorded_and_does_not_stop_the_run(monkeypatch):
    """
    An installer or a self-restart replaces the process. Reading that as a
    sandbox failure ended runs at the exact moment the second stage began.
    """
    exp = _explorer()
    exp._target_pid = 4242
    monkeypatch.setattr(exp, "_resolve_target_pid", lambda: 5151)

    exp._check_target_pid()

    assert exp._target_pid == 5151
    assert exp._target_pid_changes == 1
    assert exp._stop_reason is None


def test_an_unchanged_pid_is_not_reported_as_a_change(monkeypatch):
    exp = _explorer()
    exp._target_pid = 4242
    monkeypatch.setattr(exp, "_resolve_target_pid", lambda: 4242)
    exp._check_target_pid()
    assert exp._target_pid_changes == 0


def test_an_unreadable_pid_leaves_the_last_known_one_alone(monkeypatch):
    """A pid reading that fails is a missing fact, not a process change."""
    exp = _explorer()
    exp._target_pid = 4242
    monkeypatch.setattr(exp, "_resolve_target_pid", lambda: 0)
    exp._check_target_pid()
    assert exp._target_pid == 4242
    assert exp._target_pid_changes == 0


def test_the_first_reading_establishes_the_pid_without_claiming_a_change(monkeypatch):
    exp = _explorer()
    monkeypatch.setattr(exp, "_resolve_target_pid", lambda: 777)
    exp._check_target_pid()
    assert exp._target_pid == 777
    assert exp._target_pid_changes == 0


def test_the_pid_is_rechecked_when_the_walk_returns_from_a_boundary():
    import inspect

    from sudarshan_core.engines.agentic_explorer import AgenticExplorer

    source = inspect.getsource(AgenticExplorer.start)
    assert "_check_target_pid" in source
    assert "was_out_of_scope" in source


# ── 7. Prose is not a button ──────────────────────────────────────────────────

_VPN_BODY = (
    "Dropper wants to set up a VPN connection that allows it to monitor "
    "network traffic. Only accept if you trust the source."
)


def test_the_dialog_body_does_not_outrank_the_button_beside_it():
    """
    The AOSP VPN consent body contains every affirmative keyword this module
    knows. On a dialog whose body sits in a clickable container it scored as
    high as OK, and the victim tapped the sentence instead of the button.
    """
    body = score_ui_node(_VPN_BODY, "", "", "android.widget.TextView", "VPN_REQUEST")
    button = score_ui_node("OK", "", "", "android.widget.Button", "VPN_REQUEST")
    assert 0 < body < button


def test_a_long_caption_on_a_real_button_is_still_a_button():
    """
    Consent buttons genuinely carry long captions - the device-admin screen's
    is a full clause. The guard keys on the control type, not on length alone.
    """
    label = "Activate this device admin app and allow it to manage the device"
    assert len(label) > 60
    assert score_ui_node(label, "", "", "android.widget.Button") > score_ui_node(
        label, "", "", "android.widget.TextView"
    )


def test_a_short_caption_is_never_treated_as_prose():
    assert score_ui_node(
        "Activate this device admin app", "", "", "android.widget.TextView"
    ) == score_ui_node("Activate this device admin app", "", "", "")


def test_the_button_wins_the_ranking_on_a_real_vpn_dialog():
    nodes = [
        _Node(text="Connection request", class_name="android.widget.TextView"),
        _Node(text=_VPN_BODY, class_name="android.widget.TextView"),
        _Node(text="Cancel", class_name="android.widget.Button"),
        _Node(text="OK", class_name="android.widget.Button"),
    ]
    ranked = rank_action_candidates(nodes, "VPN_REQUEST")
    assert ranked[0][0].text == "OK"
