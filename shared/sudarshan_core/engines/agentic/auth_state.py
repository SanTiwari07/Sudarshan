"""
SUDARSHAN - Explicit authentication state for the synthetic-victim walk.

``login_outcome`` is one string with four values ("not_attempted", "retrying",
"rejected", "accepted") and it is only written when a submit has already
happened. Everything before that - a login screen recognised, one of two fields
filled, an OTP prompt appeared - was invisible, so the run could not tell
"nothing has been tried" from "the username is in and the password box is still
empty", and could not say why it was about to press a button.

Worse, "accepted" was reachable by pressing Login and seeing the activity
change. An activity change is not authentication: an error dialog is a new
activity too. :meth:`AuthStateMachine.on_submit_result` therefore requires an
observable transition into an authenticated surface, and a screen that merely
moved leaves the state at SUBMISSION_PENDING.

This machine is a VIEW over what the walk already observes. It owns no device
handle, performs no I/O and decides nothing on its own - the explorer feeds it
verified actions and it answers "where are we in the login". `login_outcome`
keeps its exact old values and is derived from this state, so nothing that
reads it has to change.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

__all__ = [
    "AuthState",
    "AuthStateMachine",
    "AuthTransition",
]


class AuthState(str, Enum):
    """Where the walk is in the authentication workflow."""

    UNKNOWN = "UNKNOWN"
    CREDENTIALS_REQUIRED = "CREDENTIALS_REQUIRED"
    CREDENTIALS_PARTIALLY_FILLED = "CREDENTIALS_PARTIALLY_FILLED"
    CREDENTIALS_FILLED = "CREDENTIALS_FILLED"
    SUBMISSION_PENDING = "SUBMISSION_PENDING"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    OTP_REQUIRED = "OTP_REQUIRED"
    OTP_FILLED = "OTP_FILLED"
    MFA_PENDING = "MFA_PENDING"
    AUTHENTICATED = "AUTHENTICATED"
    SESSION_ACTIVE = "SESSION_ACTIVE"
    #: The app cannot authenticate for a reason outside the sample: an SMS
    #: gateway that will never deliver, a backend that is gone. Distinct from
    #: AUTHENTICATION_FAILED, which means the app rejected the credentials.
    #: Retrying the first is pointless; retrying the second is meaningless.
    AUTHENTICATION_BLOCKED_EXTERNAL_SERVICE = "AUTHENTICATION_BLOCKED_EXTERNAL_SERVICE"


#: States from which the walk has an authenticated surface to explore.
_AUTHENTICATED_STATES = frozenset({AuthState.AUTHENTICATED, AuthState.SESSION_ACTIVE})

#: States in which offering credentials again is pointless.
_TERMINAL_STATES = frozenset({
    AuthState.AUTHENTICATION_FAILED,
    AuthState.AUTHENTICATION_BLOCKED_EXTERNAL_SERVICE,
})

#: AuthState → the legacy ``login_outcome`` string. The legacy vocabulary is
#: coarser, so this is many-to-one; it exists to keep frida_sandbox's report
#: key and the existing tests working unchanged.
_LEGACY_OUTCOME: Dict[AuthState, str] = {
    AuthState.UNKNOWN: "not_attempted",
    AuthState.CREDENTIALS_REQUIRED: "not_attempted",
    AuthState.CREDENTIALS_PARTIALLY_FILLED: "not_attempted",
    AuthState.CREDENTIALS_FILLED: "not_attempted",
    AuthState.SUBMISSION_PENDING: "retrying",
    AuthState.AUTHENTICATION_FAILED: "rejected",
    AuthState.OTP_REQUIRED: "retrying",
    AuthState.OTP_FILLED: "retrying",
    AuthState.MFA_PENDING: "retrying",
    AuthState.AUTHENTICATED: "accepted",
    AuthState.SESSION_ACTIVE: "accepted",
    AuthState.AUTHENTICATION_BLOCKED_EXTERNAL_SERVICE: "exhausted",
}


@dataclass
class AuthTransition:
    """One recorded state change, kept so the report can explain the walk."""

    from_state: AuthState
    to_state: AuthState
    reason: str
    evidence: str = ""
    elapsed: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from": self.from_state.value,
            "to": self.to_state.value,
            "reason": self.reason,
            "evidence": self.evidence[:200],
            "elapsed": self.elapsed,
        }


@dataclass
class AuthStateMachine:
    """
    Tracks the authentication workflow across one investigation.

    Fed by the explorer after VERIFIED actions only. An action that did not
    execute did not fill a field, and a state advanced on an unverified action
    is the same bug as calling a login successful because a button was pressed.
    """

    state: AuthState = AuthState.UNKNOWN
    history: List[AuthTransition] = field(default_factory=list)
    #: Semantic field types filled on the credential form so far, so
    #: "partially filled" is a fact rather than a guess.
    filled_fields: Set[str] = field(default_factory=set)
    #: Field types the current screen is asking for.
    required_fields: Set[str] = field(default_factory=set)
    submit_count: int = 0

    # ── Transition ──────────────────────────────────────────────────────────

    def _transition(
        self, to: AuthState, reason: str, evidence: str = "", elapsed: str = "",
    ) -> bool:
        """Move to `to`. Returns whether the state actually changed."""
        if to is self.state:
            return False
        transition = AuthTransition(
            from_state=self.state, to_state=to, reason=reason,
            evidence=evidence, elapsed=elapsed,
        )
        self.history.append(transition)
        logger.info(
            "[AuthState] %s -> %s (%s)", self.state.value, to.value, reason,
        )
        self.state = to
        return True

    # ── Observations ────────────────────────────────────────────────────────

    def on_screen(
        self,
        *,
        screen_type: str = "",
        required_fields: Optional[Set[str]] = None,
        screen_text: str = "",
        elapsed: str = "",
    ) -> AuthState:
        """
        Record what the current screen is asking for.

        An OTP prompt appearing after a submit is the strongest evidence that
        the first factor was ACCEPTED - an app does not ask for a one-time code
        from someone it has already turned away - so it advances the state even
        though nothing has been typed yet.
        """
        from sudarshan_core.engines.agentic.field_taxonomy import FieldType

        st = (screen_type or "").upper()
        self.required_fields = set(required_fields or ())

        otp_types = {
            FieldType.OTP.value, FieldType.EMAIL_OTP.value,
            FieldType.VERIFICATION_CODE.value,
        }
        wants_otp = bool(self.required_fields & otp_types) or st in {"OTP", "MFA"}

        if wants_otp and self.state not in _AUTHENTICATED_STATES:
            self._transition(
                AuthState.OTP_REQUIRED,
                "screen requests a one-time code",
                evidence=st or "otp fields present",
                elapsed=elapsed,
            )
            return self.state

        if self._is_authenticated_surface(screen_text, st):
            self._transition(
                AuthState.SESSION_ACTIVE if self.state in _AUTHENTICATED_STATES
                else AuthState.AUTHENTICATED,
                "authenticated surface observed",
                evidence=st, elapsed=elapsed,
            )
            return self.state

        credential_types = {
            FieldType.PASSWORD.value, FieldType.PIN.value, FieldType.MPIN.value,
            FieldType.PASSCODE.value,
        }
        wants_credentials = bool(self.required_fields & credential_types) or st in {
            "BANK_LOGIN", "LOGIN",
        }
        if wants_credentials and self.state in {
            AuthState.UNKNOWN, AuthState.AUTHENTICATION_FAILED,
        }:
            self._transition(
                AuthState.CREDENTIALS_REQUIRED,
                "credential form observed",
                evidence=st, elapsed=elapsed,
            )
        return self.state

    def on_field_filled(
        self, field_type: str, *, verified: bool = True, elapsed: str = "",
    ) -> AuthState:
        """
        Record that a field was populated AND the population was verified.

        `verified=False` is deliberately a no-op: an unverified type is exactly
        the case this model exists to stop being counted as progress.
        """
        from sudarshan_core.engines.agentic.field_taxonomy import FieldType

        if not verified:
            return self.state

        self.filled_fields.add(str(field_type))

        otp_types = {
            FieldType.OTP.value, FieldType.EMAIL_OTP.value,
            FieldType.VERIFICATION_CODE.value,
        }
        if str(field_type) in otp_types:
            self._transition(
                AuthState.OTP_FILLED, "one-time code entered", elapsed=elapsed,
            )
            return self.state

        if self.state in _AUTHENTICATED_STATES:
            return self.state

        # "Filled" means every field the screen asked for has a verified value.
        # With nothing known about what it asked for, two filled fields is the
        # ordinary identifier+secret pair and is treated as complete.
        outstanding = self.required_fields - self.filled_fields
        if self.required_fields and not outstanding:
            self._transition(
                AuthState.CREDENTIALS_FILLED,
                "all requested credential fields populated",
                evidence=",".join(sorted(self.filled_fields)), elapsed=elapsed,
            )
        elif not self.required_fields and len(self.filled_fields) >= 2:
            self._transition(
                AuthState.CREDENTIALS_FILLED,
                "identifier and secret populated",
                evidence=",".join(sorted(self.filled_fields)), elapsed=elapsed,
            )
        else:
            self._transition(
                AuthState.CREDENTIALS_PARTIALLY_FILLED,
                "credential field populated",
                evidence=",".join(sorted(self.filled_fields)), elapsed=elapsed,
            )
        return self.state

    def on_submit(self, *, elapsed: str = "") -> AuthState:
        """A credential form was submitted. This is NOT authentication."""
        self.submit_count += 1
        if self.state is AuthState.OTP_FILLED:
            self._transition(
                AuthState.MFA_PENDING, "one-time code submitted", elapsed=elapsed,
            )
        else:
            self._transition(
                AuthState.SUBMISSION_PENDING, "credentials submitted",
                elapsed=elapsed,
            )
        return self.state

    def on_submit_result(
        self,
        *,
        rejected: bool = False,
        success_hint: bool = False,
        activity_changed: bool = False,
        screen_type: str = "",
        screen_text: str = "",
        external_block: bool = False,
        elapsed: str = "",
    ) -> AuthState:
        """
        Judge what the app said after a submit.

        The ordering matters and encodes the rule that a click is not a login:

        1. An explicit rejection is an answer. Believe it.
        2. An OTP prompt means the first factor was accepted.
        3. An authenticated LANDMARK ("Logout", "Account Summary") means
           authenticated. A changed activity on its own does NOT - it is
           equally consistent with an error screen - so it leaves the state at
           SUBMISSION_PENDING and the walk keeps looking.
        """
        st = (screen_type or "").upper()

        if external_block:
            self._transition(
                AuthState.AUTHENTICATION_BLOCKED_EXTERNAL_SERVICE,
                "authentication depends on an unavailable external service",
                evidence=screen_text[:120], elapsed=elapsed,
            )
            return self.state

        if rejected:
            self._transition(
                AuthState.AUTHENTICATION_FAILED,
                "application stated the credentials are invalid",
                evidence=screen_text[:120], elapsed=elapsed,
            )
            # A rejected attempt un-fills the form: the next attempt starts over.
            self.filled_fields.clear()
            return self.state

        if st in {"OTP", "MFA"}:
            self._transition(
                AuthState.OTP_REQUIRED,
                "one-time code requested after submit - first factor accepted",
                evidence=st, elapsed=elapsed,
            )
            return self.state

        if success_hint or self._is_authenticated_surface(screen_text, st):
            self._transition(
                AuthState.AUTHENTICATED,
                "authenticated surface reached after submit",
                evidence=screen_text[:120], elapsed=elapsed,
            )
            return self.state

        # An activity change alone proves only that something happened.
        if activity_changed:
            logger.debug(
                "[AuthState] activity changed after submit but no authenticated "
                "landmark observed - holding at %s", self.state.value,
            )
        return self.state

    def on_session_activity(self, *, elapsed: str = "") -> AuthState:
        """An authenticated surface was successfully explored."""
        if self.state is AuthState.AUTHENTICATED:
            self._transition(
                AuthState.SESSION_ACTIVE, "authenticated surface explored",
                elapsed=elapsed,
            )
        return self.state

    def on_login_form_rearmed(self) -> None:
        """A retry is starting: the form is empty again."""
        self.filled_fields.clear()
        if self.state in {AuthState.SUBMISSION_PENDING, AuthState.CREDENTIALS_FILLED}:
            self._transition(
                AuthState.CREDENTIALS_REQUIRED, "login form re-armed for retry",
            )

    # ── Queries ─────────────────────────────────────────────────────────────

    @staticmethod
    def _is_authenticated_surface(screen_text: str, screen_type: str = "") -> bool:
        from sudarshan_core.engines.agentic.credentials import login_succeeded_hint

        if screen_type in {"DASHBOARD", "ACCOUNT_SUMMARY"}:
            return True
        return login_succeeded_hint(screen_text or "")

    @property
    def is_authenticated(self) -> bool:
        return self.state in _AUTHENTICATED_STATES

    @property
    def is_terminal(self) -> bool:
        """Whether offering credentials again would be pointless."""
        return self.state in _TERMINAL_STATES

    @property
    def legacy_outcome(self) -> str:
        """The pre-existing ``login_outcome`` string for this state."""
        return _LEGACY_OUTCOME.get(self.state, "not_attempted")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "auth_state": self.state.value,
            "login_outcome": self.legacy_outcome,
            "submit_count": self.submit_count,
            "filled_fields": sorted(self.filled_fields),
            "required_fields": sorted(self.required_fields),
            "transitions": [t.to_dict() for t in self.history],
        }
