"""The process environment must outrank a .env file loaded by the correlator."""

import os

from sudarshan_core.services import threat_correlator as tc


def test_env_file_does_not_override_process_env(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("SUDARSHAN_PRECEDENCE_PROBE=from_file\nSUDARSHAN_ONLY_IN_FILE=filled\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SUDARSHAN_PRECEDENCE_PROBE", "from_process")
    monkeypatch.delenv("SUDARSHAN_ONLY_IN_FILE", raising=False)

    tc._load_env_if_needed()

    assert os.environ["SUDARSHAN_PRECEDENCE_PROBE"] == "from_process"
