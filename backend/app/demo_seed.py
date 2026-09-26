"""
Optional RBAC demo accounts - idempotent startup seed.

Enable with SUDARSHAN_SEED_DEMO_USERS=true (see .env.example). Every password
must come from the environment: there are no defaults, because a default
password in a public repository is a published credential. Refused outright
when SUDARSHAN_ENV=production.
Does not reset passwords for existing users.
"""

from __future__ import annotations

import logging
import os

from app.auth.auth import hash_password
from app.db.database import (
    create_user,
    get_user_by_username,
    update_user_role,
    username_exists,
)

logger = logging.getLogger(__name__)


def _truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


async def _ensure_user(username: str, plain_password: str, role: str) -> None:
    if not username or not plain_password:
        logger.warning("[DemoSeed] Skipping user %r - username or password empty", username)
        return
    if len(plain_password) < 8:
        logger.warning("[DemoSeed] Skipping user %r - password must be at least 8 characters", username)
        return

    if await username_exists(username):
        user = await get_user_by_username(username)
        if user and user.get("role") != role:
            await update_user_role(user["id"], role)
            logger.info("[DemoSeed] Updated role for %r -> %s", username, role)
        return

    hashed = hash_password(plain_password)
    await create_user(username, hashed, role=role)
    logger.info("[DemoSeed] Created demo user %r (role=%s)", username, role)


async def seed_demo_users() -> None:
    """Create soclead / analyst1 (and optional boi_* aliases) for RBAC demos."""
    if not _truthy("SUDARSHAN_SEED_DEMO_USERS"):
        return
    if os.getenv("SUDARSHAN_ENV", "").strip().lower() == "production":
        logger.error(
            "[DemoSeed] SUDARSHAN_SEED_DEMO_USERS is set in production - refusing "
            "to create demo accounts."
        )
        return

    soc_user = os.getenv("DEMO_SOCLEAD_USERNAME", "soclead").strip()
    soc_pass = os.getenv("DEMO_SOCLEAD_PASSWORD", "").strip()
    analyst_user = os.getenv("DEMO_ANALYST_USERNAME", "analyst1").strip()
    analyst_pass = os.getenv("DEMO_ANALYST_PASSWORD", "").strip()

    await _ensure_user(soc_user, soc_pass, "soc_lead")
    await _ensure_user(analyst_user, analyst_pass, "analyst")

    if _truthy("DEMO_SEED_BOI_ALIASES"):
        await _ensure_user(
            os.getenv("DEMO_BOI_ADMIN_USERNAME", "boi_admin").strip(),
            os.getenv("DEMO_BOI_ADMIN_PASSWORD", "").strip(),
            "admin",
        )
        await _ensure_user(
            os.getenv("DEMO_BOI_SOCLEAD_USERNAME", "boi_soclead").strip(),
            os.getenv("DEMO_BOI_SOCLEAD_PASSWORD", "").strip(),
            "soc_lead",
        )
        await _ensure_user(
            os.getenv("DEMO_BOI_ANALYST_USERNAME", "boi_analyst").strip(),
            os.getenv("DEMO_BOI_ANALYST_PASSWORD", "").strip(),
            "analyst",
        )

    logger.info("[DemoSeed] Demo users processed. SOC: %s | Analyst: %s", soc_user, analyst_user)
