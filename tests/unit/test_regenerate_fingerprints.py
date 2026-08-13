"""String extraction used by scripts/regenerate_fingerprints.py."""

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = REPO_ROOT / "scripts" / "regenerate_fingerprints.py"


def _load():
    spec = importlib.util.spec_from_file_location("regenerate_fingerprints", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["regenerate_fingerprints"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


pytestmark = pytest.mark.skipif(not _SCRIPT.is_file(), reason="generator script missing")
gen = _load()


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "Screen.tsx"
    path.write_text(body, encoding="utf-8")
    return path


def test_extracts_inline_jsx_text_and_props(tmp_path):
    found = gen.extract_source_strings(
        _write(
            tmp_path,
            """
            export const Login = () => (
              <div>
                <Header title="YONO SBI" />
                <p>Available Balance</p>
                <InputField label="Username" placeholder="Enter username" />
              </div>
            );
            """,
        )
    )
    for expected in ("YONO SBI", "Available Balance", "Username", "Enter username"):
        assert expected in found, expected


def test_extracts_multiline_jsx_text(tmp_path):
    """
    Regression: prettier puts JSX text on its own line. A newline-excluding
    pattern silently dropped most labels of a well-formatted screen - Kotak's
    login screen yielded one string instead of seven.
    """
    found = gen.extract_source_strings(
        _write(
            tmp_path,
            """
            <div>
              <h1 className="text-2xl">
                Welcome back
              </h1>
              <p style={{ color: 'var(--color-text)' }}>
                Enter your CRN or Customer ID to login
              </p>
              <button>
                Continue
              </button>
            </div>
            """,
        )
    )
    assert "Welcome back" in found
    assert "Enter your CRN or Customer ID to login" in found
    assert "Continue" in found


def test_rejects_styling_and_code_tokens(tmp_path):
    found = gen.extract_source_strings(
        _write(
            tmp_path,
            """
            <div className="flex flex-col" style={{ padding: '24px' }}>
              <p>Transfer</p>
            </div>
            """,
        )
    )
    assert "Transfer" in found
    for noise in ("flex flex-col", "24px", "flex", "column"):
        assert noise not in found, noise


@pytest.mark.parametrize(
    "value",
    [
        "XXXX 1234",
        "A/C No: XXXXXX4321",
        "Last login: 12 Aug 2026, 10:30 AM",
        "Good Morning, Rahul",
        "Welcome back, Priya",
    ],
)
def test_rejects_prototype_mock_data(value):
    """A real clone shows the victim's own data, so mock values can never match."""
    assert gen._is_ui_label(value) is False


@pytest.mark.parametrize(
    "value",
    ["Available Balance", "Enter MPIN", "Forgot CRN?", "Pay Bills", "Welcome back"],
)
def test_accepts_stable_ui_labels(value):
    assert gen._is_ui_label(value) is True


def test_comments_are_ignored(tmp_path):
    found = gen.extract_source_strings(
        _write(
            tmp_path,
            """
            {/* Account Summary Card */}
            <div>
              // Quick Actions
              <p>Recent Activity</p>
            </div>
            """,
        )
    )
    assert "Recent Activity" in found
    assert "Account Summary Card" not in found
