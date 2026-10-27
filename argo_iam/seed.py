"""Demo data: one user per role, with authenticators already enrolled."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from argo_iam.auth.totp import TOTP
from argo_iam.container import Container
from argo_iam.users.models import Role

DEMO_PASSWORD = "ArgoDemo!2026"


@dataclass(frozen=True)
class DemoUser:
    username: str
    display_name: str
    role: Role
    enrol_mfa: bool = True


DEMO_USERS: List[DemoUser] = [
    DemoUser("alice", "Alice Admin", Role.ADMIN),
    DemoUser("sam", "Sam Security", Role.ADMIN),
    DemoUser("oscar", "Oscar Operator", Role.OPERATOR),
    DemoUser("vera", "Vera Viewer", Role.VIEWER),
    # Has no authenticator yet, to demonstrate first-login MFA enrolment.
    DemoUser("nina", "Nina Newcomer", Role.OPERATOR, enrol_mfa=False),
]


def seed_demo_users(c: Container) -> List[str]:
    """Create missing demo users. Returns the usernames that were created."""
    created = []
    for demo in DEMO_USERS:
        if c.users_repo.get_by_username(demo.username) is not None:
            continue
        user = c.users.provision(
            demo.username, demo.display_name, f"{demo.username}@example.com",
            DEMO_PASSWORD, demo.role,
        )
        if demo.enrol_mfa:
            user.mfa_secret = TOTP.generate_secret()
            user.mfa_enabled = True
            c.users_repo.save(user)
        created.append(demo.username)
    return created
