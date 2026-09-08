"""
SUDARSHAN - the deterministic Test Input Profile.

Module named `input_profile` rather than `test_input_profile` on purpose: a
module whose name starts with `test_` is collected by pytest as a test file,
and a production module that pytest imports as a test suite is a trap waiting
for whoever next runs a bare `pytest` from the repo root.

What this is for
----------------
A dynamic run has to type SOMETHING into the forms a sample puts in front of
it, and what it types has to satisfy three constraints at once:

1. It must fit the field. A four-digit MPIN box does not accept six digits, and
   a form that rejects its input reads to the walk as "the app refused us" when
   in fact the walk never made a valid attempt. The semantic classifier
   (:mod:`field_classifier`, :mod:`field_taxonomy`) answers this half.
2. It must be obviously, unmistakably synthetic. Every value here is inert by
   construction - the email is on ``.invalid``, which RFC 2606 reserves and
   which no resolver will ever answer; the account and card numbers are
   non-transactable test values; the phone number is from the reserved
   555-01xx range. Nothing here can authenticate to a real service, and nothing
   here can cause a real OTP to be sent.
3. It must be reproducible when an analyst needs a run to replay byte for byte.

This module answers (2) and (3) with a fixed table.

Why it is not the default
-------------------------
:mod:`victim_profile` draws a coherent identity per run, and that is a
deliberate anti-fingerprinting property, not an oversight: a sample that sees
the same login string typed into its box on every analysis can detect the
sandbox on one string compare and go dormant, which costs far more than
reproducibility buys. See that module's own note.

So the two coexist and the operator chooses::

    SUDARSHAN_TEST_INPUT_PROFILE=persona          # default - rotating identity
    SUDARSHAN_TEST_INPUT_PROFILE=deterministic    # this table, byte-reproducible

Both are synthetic, both are enrolled in the redaction set, and neither can
reach real infrastructure. The difference is only whether the identity varies.

What this is NOT
----------------
Not a credential store, and not a way to log in to anything. The purpose of
filling a login form during analysis is to get PAST it and observe what the
sample does next - accessibility abuse, overlay draw, SMS interception, C2
traffic. When an app refuses these values the answer is recorded as
AUTH_FLOW_REJECTED and the walk moves to another branch; it does not retry
in the hope of guessing something real.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, Optional

from sudarshan_core.engines.agentic.field_taxonomy import FieldType

logger = logging.getLogger(__name__)

__all__ = [
    "DETERMINISTIC_TEST_INPUTS",
    "deterministic_profile_enabled",
    "test_input_for",
    "all_test_input_values",
]


def deterministic_profile_enabled() -> bool:
    """
    Whether the fixed table replaces the rotating synthetic persona.

    Read at call time rather than import time so a test can switch modes
    without reloading the module.
    """
    return os.getenv("SUDARSHAN_TEST_INPUT_PROFILE", "persona").strip().lower() in {
        "deterministic", "fixed", "static",
    }


#: The fixed value for each semantic field type.
#:
#: Chosen to be legible in a screenshot - an analyst looking at the evidence
#: should be able to tell at a glance that the form was filled by the harness
#: and not by a person - and inert by construction:
#:
#:   * ``.invalid`` is reserved by RFC 2606 and can never resolve or receive
#:     mail, so a sample that exfiltrates the form contents, or triggers a
#:     "forgot password" flow, reaches nothing that belongs to anybody;
#:   * ``+91 5550100000`` is in the reserved fictitious range, so no OTP can be
#:     delivered to a real handset;
#:   * the account, card, IFSC and UPI values are structurally valid enough to
#:     pass a client-side format check and are not routable by any real
#:     institution;
#:   * the card number uses the 4111 1111 1111 1111 test PAN, which every
#:     processor recognises as a test value and none will transact.
DETERMINISTIC_TEST_INPUTS: Dict[FieldType, str] = {
    # -- Identity ------------------------------------------------------------
    FieldType.USERNAME:        "demo_user",
    FieldType.USER_ID:         "demo_user",
    FieldType.LOGIN_ID:        "demo_user",
    FieldType.CUSTOMER_ID:     "DEMO0000001",
    FieldType.CUSTOMER_NUMBER: "DEMO0000001",
    FieldType.CIF:             "DEMO0000001",

    # -- Secrets -------------------------------------------------------------
    FieldType.EMAIL:           "analyst.test@sudarshan.invalid",
    FieldType.PASSWORD:        "DemoPass123!",
    FieldType.PIN:             "1234",
    FieldType.MPIN:            "1234",
    FieldType.PASSCODE:        "1234",

    # -- One-time / recovery codes -------------------------------------------
    FieldType.OTP:               "123456",
    FieldType.EMAIL_OTP:         "123456",
    FieldType.VERIFICATION_CODE: "123456",
    FieldType.RECOVERY_CODE:     "DEMOCODE",

    # -- Contact -------------------------------------------------------------
    # Reserved fictitious range. No real handset receives anything sent here.
    FieldType.PHONE:  "5550100000",
    FieldType.MOBILE: "5550100000",

    # -- Person --------------------------------------------------------------
    FieldType.FULL_NAME:   "Sudarshan Demo User",
    FieldType.FIRST_NAME:  "Sudarshan",
    FieldType.LAST_NAME:   "User",
    # Distinct from FULL_NAME on purpose: a KYC or challan form that asks for a
    # parent's name is cross-checking the identity, and a form naming the same
    # person as themselves and their own mother is exactly what a validator
    # catches.
    FieldType.MOTHER_NAME: "Demo Mother",
    FieldType.FATHER_NAME: "Demo Father",

    # -- Demographics --------------------------------------------------------
    FieldType.DATE_OF_BIRTH: "01/01/1990",
    FieldType.ADDRESS:       "1 Analysis Lane",
    FieldType.CITY:          "Pune",
    FieldType.STATE:         "Maharashtra",
    FieldType.POSTAL_CODE:   "411001",

    # -- Instruments ---------------------------------------------------------
    FieldType.ACCOUNT_NUMBER: "000000000000",
    FieldType.CARD_NUMBER:    "4111111111111111",
    FieldType.CARD_EXPIRY:    "12/30",
    FieldType.CARD_CVV:       "123",

    # -- Payment rails -------------------------------------------------------
    FieldType.IFSC:   "DEMO0000001",
    FieldType.UPI_ID: "demo.user@demoupi",

    # -- Transfer counterparty ----------------------------------------------
    FieldType.BENEFICIARY_NAME:    "Demo Beneficiary",
    FieldType.BENEFICIARY_ACCOUNT: "000000000001",
}

#: What an UNKNOWN field receives.
#:
#: Deliberately not random text. The instruction that matters here is: never
#: fill a field with noise merely because the field is unknown. A caller that
#: cannot infer a type either skips the field or types this, which is legible
#: as harness input in a screenshot and cannot be mistaken for a credential.
GENERIC_TEST_VALUE: str = "demo_input"


def test_input_for(
    field_type: FieldType,
    *,
    max_length: Optional[int] = None,
    min_length: Optional[int] = None,
    numeric_only: bool = False,
) -> str:
    """
    The fixed value for a field type, trimmed or padded to fit it.

    Length handling is the whole reason this is a function rather than a dict
    lookup. `field_hint="password"` is the same string for a four-digit MPIN
    and a twelve-character login password, and a value that does not fit is
    silently truncated by the field - which submits a half-entered secret and
    reads back as "the app rejected our credentials".

    Trimming a SECRET keeps it deterministic: "123456" in a four-digit box
    becomes "1234", not a fresh random four digits, so the same field gets the
    same value on a retry.
    """
    value = DETERMINISTIC_TEST_INPUTS.get(field_type, GENERIC_TEST_VALUE)

    if numeric_only and not value.isdigit():
        digits = "".join(ch for ch in value if ch.isdigit())
        value = digits or "1234"

    if max_length and len(value) > max_length:
        value = value[:max_length]
    if min_length and len(value) < min_length:
        # Pad with a repeat of the value's own alphabet rather than a random
        # filler, so the result stays reproducible and stays legible.
        pad_char = "0" if value.isdigit() else "x"
        value = value + pad_char * (min_length - len(value))
    return value


def all_test_input_values() -> set:
    """
    Every value this table can issue, for log redaction.

    A value that can be typed must be a value that can be redacted, whether or
    not it is real - the audit log has no way to tell, and an operator reading
    a report should not have to either.
    """
    return set(DETERMINISTIC_TEST_INPUTS.values()) | {GENERIC_TEST_VALUE}
