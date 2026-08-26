"""
A WebView app's network traffic must not be invisible.

The gap: a page that submits with `fetch()` or `XMLHttpRequest` issues its
requests through Chromium, not through `java.net`, OkHttp or Retrofit - so
every Java-side network hook the agent installs is blind to it, and
`WebView.loadUrl` only ever sees the first navigation.

Measured on a live e-challan sample: 69 hooks installed, the victim filled and
submitted a four-field form, and not one network event fired. The same form,
watched from inside the page, was posting

    https://jsonserv.biz/app-store?id=<pkg>&android_id=<device id>

with a base64 body decoding to the victim's full name, mobile number, mother's
name and date of birth. That is the single most important thing the sample
does, and nothing in the report mentioned it.

These assertions are made against the COMPILED BUNDLE as well as the source,
because the bundle is what is actually pushed to the device - a fix present
only in the source would be a fix that never runs.
"""

import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

_HOOKS = _ROOT / "shared" / "sudarshan_core" / "engines" / "frida_hooks"
_SOURCE = _HOOKS / "banking_trojan.js"
_BUNDLE = _HOOKS / "banking_trojan.bundle.js"


@pytest.fixture(scope="module")
def source() -> str:
    return _SOURCE.read_text(encoding="utf-8", errors="replace")


@pytest.fixture(scope="module")
def bundle() -> str:
    return _BUNDLE.read_text(encoding="utf-8", errors="replace")


# ─── The in-page shim exists and covers the ways a page can make a request ───

@pytest.mark.parametrize("api", [
    "window.fetch",                 # modern
    "XMLHttpRequest.prototype.open",
    "XMLHttpRequest.prototype.send",
    "navigator.sendBeacon",         # fire-and-forget exfil
    "HTMLFormElement.prototype.submit",
])
def test_the_shim_wraps_every_request_path(source, api):
    assert api in source, (
        f"{api} is not intercepted; a page using it would exfiltrate silently"
    )


def test_the_shim_is_present_in_the_compiled_bundle(bundle):
    """The bundle is what runs on the device."""
    assert "__sdsn_drain" in bundle
    assert "window.fetch" in bundle


def test_the_shim_is_idempotent(source):
    """
    A page that navigates loses `window`, so the shim is re-sent on every
    drain. Re-wrapping an already-wrapped fetch would nest the wrappers and
    report one request many times.
    """
    assert "if(window.__sdsn)" in source.replace(" ", "")


def test_password_fields_are_redacted_before_they_leave_the_page(source):
    """
    §P28: the forensic record carries the field TYPE and the value SOURCE, not
    the secret. A form serialiser that shipped the password box verbatim would
    write a credential into the evidence store.
    """
    assert '"<redacted>"' in source or "'<redacted>'" in source
    assert 'el.type==="password"' in source.replace(" ", "")


def test_the_shim_only_observes(source):
    """
    Every wrapper calls through to the original.

    An analysis that blocks or rewrites a request is measuring itself, not the
    sample.
    """
    for passthrough in (
        "of.apply(this,arguments)",
        "xo.apply(this,arguments)",
        "xs.apply(this,arguments)",
        "fsub.apply(this,arguments)",
    ):
        assert passthrough in source.replace(" ", ""), passthrough


# ─── Captured requests are reported as network evidence ─────────────────────

def test_captured_requests_emit_into_the_scored_network_category(source):
    """
    `network` carries BFCI weight, so an in-page C2 call reaches the score
    rather than sitting in an unscored bucket.
    """
    from sudarshan_core.engines.bfci_scorer import BFCI_WEIGHTS

    idx = source.index("WebView.js.")
    window = source[max(0, idx - 800): idx]
    assert "emit('network'" in window
    assert "network" in BFCI_WEIGHTS


def test_the_request_record_names_its_url_method_and_body(source):
    """An analyst needs WHERE it went and WHAT went with it."""
    idx = source.index("'WebView.js.'")
    block = source[idx: idx + 900]
    for field in ("url:", "method:", "body_preview:", "ioc:"):
        assert field in block, field


# ─── The trigger has to be one that actually fires ──────────────────────────

def test_the_drain_is_hooked_on_the_views_own_class(source):
    """
    Hooking android.webkit.WebView.onTouchEvent is not enough.

    A subclass that overrides onTouchEvent without calling super never reaches
    the base implementation, so the base hook installs, reports success, and
    silently never fires. Measured on a Capacitor app: with both hooked,
    com.getcapacitor.CapacitorWebView.onTouchEvent fired on every tap while the
    framework class fired zero times. The class is taken from the live
    instance, so nothing here is framework-specific.
    """
    assert "sdsnHookTouchFor" in source
    assert "wv.$className" in source


def test_touch_hooks_are_installed_outside_the_heap_walk(source):
    """
    Replacing a method from inside Java.choose's onMatch reports success and
    then never fires. The class names are collected during the walk and hooked
    after it finishes.
    """
    assert "deferHooksTo" in source
    idx = source.index("function sdsnSweepForWebViews")
    block = source[idx: idx + 1200]
    assert "pendingClasses" in block
    assert block.index("Java.choose") < block.index("sdsnHookTouchFor("), (
        "hooking must happen after the enumeration, not inside onMatch"
    )


def test_the_agent_does_not_rely_on_its_own_timers(source):
    """
    `setInterval` does not fire in this agent once the script has loaded -
    measured at zero heartbeat pings over 18s against its own 3s interval. Any
    recurring work that depended on it would collect nothing, which reads in
    the report exactly like a page that made no requests.
    """
    idx = source.index("function sdsnDrainNow")
    block = source[idx: idx + 2500]
    # The CALL, not the word: the surrounding comments explain why the timer is
    # unusable and naming it there is the point.
    assert "setInterval(" not in block


def test_the_drain_is_never_driven_over_rpc(source):
    """
    An rpc call arrives on a thread that is not attached to the VM, and
    Java.choose from there HANGS rather than failing - it wedges the caller for
    the rest of the run. The rpc surface may report state, never drive work.
    """
    idx = source.index("rpc.exports")
    block = source[idx: idx + 1600]
    assert "sdsnPumpHandle()" not in block
    assert "webviewCount" in block


# ─── Java-side WebView surfaces worth reporting ─────────────────────────────

@pytest.mark.parametrize("hook", [
    "WebView.addJavascriptInterface",   # page JS gains native reach
    "WebView.postUrl",
    "WebView.loadUrl",
    "WebView.evaluateJavascript",
])
def test_the_java_side_webview_surfaces_are_hooked(bundle, hook):
    assert re.search(rf"hook: ['\"]{re.escape(hook)}['\"]", bundle), hook
