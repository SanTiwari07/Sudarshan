"""Rate limiting for the public gateway API."""

from __future__ import annotations

import os

from slowapi import Limiter
from slowapi.util import get_remote_address

_DISABLED = os.getenv("SUDARSHAN_RATE_LIMIT_DISABLED", "").lower() in (
    "1",
    "true",
    "yes",
)

limiter = Limiter(
    key_func=get_remote_address,
    enabled=not _DISABLED,
    default_limits=[],
)
