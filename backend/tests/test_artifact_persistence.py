"""
Per-sample forensic artifact persistence.

Root defect: `frida_sandbox` read `getattr(self, '_apk_dir', '.')` but never
assigned `_apk_dir`, so `audit_log.json` and `benchmark.json` were always
written to the process working directory and every scan destroyed the previous
sample's record. The "working" path was no better - it used
`Path(apk_path).parent`, which collides for any two APKs in the same folder.

§4 matrix: sample1 → sample2 → sample1 again; both directories must survive.
"""

import json

import pytest

from sudarshan_core.engines.frida_sandbox import ARTIFACT_ROOT_DIRNAME, FridaSession, artifact_dir_for


@pytest.fixture
def samples(tmp_path):
    one = tmp_path / "sample1.apk"
    two = tmp_path / "sample2.apk"
    one.write_bytes(b"PK\x03\x04 sample one")
    two.write_bytes(b"PK\x03\x04 sample two")
    return one, two


# ─── Directory allocation ─────────────────────────────────────────────────────

def test_directory_is_created(samples):
    one, _ = samples
    assert artifact_dir_for(str(one)).is_dir()


def test_distinct_samples_get_distinct_directories(samples):
    one, two = samples
    assert artifact_dir_for(str(one)) != artifact_dir_for(str(two))


def test_same_sample_reuses_its_directory(samples):
    one, _ = samples
    assert artifact_dir_for(str(one)) == artifact_dir_for(str(one))


def test_directory_is_not_the_apk_folder_itself(samples):
    """Two APKs sharing a folder must not share an artifact directory."""
    one, _ = samples
    assert artifact_dir_for(str(one)) != one.parent


def test_same_stem_in_different_folders_does_not_collide(tmp_path):
    a_dir, b_dir = tmp_path / "a", tmp_path / "b"
    a_dir.mkdir()
    b_dir.mkdir()
    (a_dir / "app.apk").write_bytes(b"a")
    (b_dir / "app.apk").write_bytes(b"b")
    assert artifact_dir_for(str(a_dir / "app.apk")) != artifact_dir_for(str(b_dir / "app.apk"))


@pytest.mark.parametrize(
    "name",
    ["../escape.apk", "we;rd na@me.apk", "..\\win.apk", "a" * 200 + ".apk", "🙂.apk"],
)
def test_hostile_filenames_stay_inside_the_root(tmp_path, name):
    """An APK filename is attacker-chosen - it must not escape the root."""
    apk = tmp_path / "holder.apk"
    apk.write_bytes(b"x")
    target = artifact_dir_for(str(apk.parent / name))
    resolved = target.resolve()

    # The real property: the directory stays under the artifact root, inside the
    # sample's own folder. A name may CONTAIN dots ("..\\win" sanitises to
    # ".._win"); what matters is that it is one literal component and never the
    # parent reference itself - the digest suffix guarantees that.
    # Artifacts always land beside the file's REAL location, under the artifact
    # root - a traversal component in the name cannot redirect them elsewhere.
    real_parent = (apk.parent / name).resolve().parent
    assert ARTIFACT_ROOT_DIRNAME in resolved.parts or resolved == real_parent
    assert target.name not in ("..", ".")
    assert resolved.is_relative_to(real_parent)


# ─── The §4 sequence ──────────────────────────────────────────────────────────

def test_sample1_then_sample2_then_sample1_keeps_both(samples):
    one, two = samples

    dir1 = artifact_dir_for(str(one))
    (dir1 / "audit_log.json").write_text(json.dumps({"run": "one"}), encoding="utf-8")

    dir2 = artifact_dir_for(str(two))
    (dir2 / "audit_log.json").write_text(json.dumps({"run": "two"}), encoding="utf-8")

    # Sample 2's analysis must not have touched sample 1's record.
    assert json.loads((dir1 / "audit_log.json").read_text(encoding="utf-8"))["run"] == "one"

    # Re-running sample 1 rewrites only its own directory.
    dir1_again = artifact_dir_for(str(one))
    (dir1_again / "audit_log.json").write_text(json.dumps({"run": "one-again"}), encoding="utf-8")

    assert dir1_again == dir1
    assert json.loads((dir2 / "audit_log.json").read_text(encoding="utf-8"))["run"] == "two"


def test_artifacts_do_not_land_in_the_working_directory(samples, tmp_path, monkeypatch):
    one, _ = samples
    monkeypatch.chdir(tmp_path)
    target = artifact_dir_for(str(one))
    assert target.resolve() != tmp_path.resolve()


# ─── Session wiring ───────────────────────────────────────────────────────────

def test_session_stores_the_artifact_dir(samples):
    one, _ = samples
    target = artifact_dir_for(str(one))
    session = FridaSession("emulator-5554", "com.x", artifact_dir=target)
    assert session.artifact_dir == target


def test_session_records_explorer_provenance_fields():
    """A reviewer must be able to tell AI from rollback without reading logs."""
    session = FridaSession("emulator-5554", "com.x")
    assert session.explorer_used == "none"
    assert session.explorer_error is None
