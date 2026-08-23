"""
Role-Based Access Control (RBAC) Definitions.
"""

from typing import Dict, List, Set
from authtime.models.schemas import RoleEnum

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    RoleEnum.ADMIN.value: {"admin:read", "admin:write", "user:read", "invoices:read"},
    RoleEnum.USER.value: {"user:read", "invoices:read"},
    RoleEnum.GUEST.value: {"invoices:read"},
    RoleEnum.SERVICE_ACCOUNT.value: {"admin:read", "invoices:read"},
}

USER_ROLES_DB: Dict[str, str] = {
    "admin1": RoleEnum.ADMIN.value,
    "user1": RoleEnum.USER.value,
    "guest1": RoleEnum.GUEST.value,
    "svc1": RoleEnum.SERVICE_ACCOUNT.value,
}


def has_permission(role: str, required_permission: str) -> bool:
    perms = ROLE_PERMISSIONS.get(role, set())
    return required_permission in perms
