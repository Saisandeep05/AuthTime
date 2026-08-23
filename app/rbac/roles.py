"""
Role Definitions and RBAC Evaluation Logic.
"""

from enum import Enum
from typing import List, Set


class Role(str, Enum):
    ADMIN = "Admin"
    USER = "User"
    GUEST = "Guest"
    SERVICE_ACCOUNT = "ServiceAccount"


ROLE_PERMISSIONS = {
    Role.ADMIN: {"READ_INVOICE", "WRITE_INVOICE", "MANAGE_USERS", "EXECUTE_SERVICE"},
    Role.USER: {"READ_INVOICE", "WRITE_INVOICE"},
    Role.GUEST: {"READ_INVOICE"},
    Role.SERVICE_ACCOUNT: {"READ_INVOICE", "EXECUTE_SERVICE"},
}


def get_role_permissions(role: str) -> Set[str]:
    try:
        r = Role(role)
        return ROLE_PERMISSIONS.get(r, set())
    except ValueError:
        return set()


def has_permission(role: str, permission: str) -> bool:
    return permission in get_role_permissions(role)
