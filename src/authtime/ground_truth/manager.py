"""
Ground Truth State Manager.

Defines the expected authorization state (ALLOW vs DENY) for any user, role, and resource at timestamp T.
"""

from typing import Dict, List, Set, Optional, Any
from authtime.models.schemas import RoleEnum, GroundTruthState
from app.rbac.roles import ROLE_PERMISSIONS, USER_ROLES_DB, has_permission


class GroundTruthStateManager:
    def __init__(self):
        self._initial_user_roles: Dict[str, str] = {
            "admin1": RoleEnum.ADMIN.value,
            "user1": RoleEnum.USER.value,
            "guest1": RoleEnum.GUEST.value,
            "svc1": RoleEnum.SERVICE_ACCOUNT.value,
        }
        self._fault_records: List[Dict[str, Any]] = []

    def reset_to_defaults(self):
        self._initial_user_roles = {
            "admin1": RoleEnum.ADMIN.value,
            "user1": RoleEnum.USER.value,
            "guest1": RoleEnum.GUEST.value,
            "svc1": RoleEnum.SERVICE_ACCOUNT.value,
        }
        self._fault_records = []

    def record_fault_event(
        self,
        fault_type: str,
        user_id: str,
        timestamp_monotonic: float,
        new_role: Optional[str] = "User",
    ):
        self._fault_records.append({
            "fault_type": fault_type,
            "user_id": user_id,
            "timestamp_monotonic": timestamp_monotonic,
            "new_role": new_role,
        })

    def get_expected_role(self, user_id: str, timestamp_monotonic: float) -> str:
        role = self._initial_user_roles.get(user_id, RoleEnum.USER.value)
        for fault in self._fault_records:
            if fault["user_id"] == user_id and timestamp_monotonic >= fault["timestamp_monotonic"]:
                role = fault["new_role"] or RoleEnum.USER.value
        return role

    def get_expected_decision(self, user_id: str, resource_path: str, timestamp_monotonic: float) -> str:
        role = self.get_expected_role(user_id, timestamp_monotonic)
        req_perm = "admin:read" if resource_path.startswith("/admin") else "invoices:read"
        return "ALLOW" if has_permission(role, req_perm) else "DENY"

    def get_ground_truth_state(self, user_id: str, resource_path: str, timestamp_monotonic: float) -> GroundTruthState:
        role_str = self.get_expected_role(user_id, timestamp_monotonic)
        perms = list(ROLE_PERMISSIONS.get(role_str, set()))
        decision = self.get_expected_decision(user_id, resource_path, timestamp_monotonic)

        return GroundTruthState(
            timestamp_monotonic=timestamp_monotonic,
            user_id=user_id,
            expected_role=RoleEnum(role_str) if role_str in RoleEnum._value2member_map_ else RoleEnum.USER,
            expected_permissions=perms,
            resource_path=resource_path,
            expected_decision=decision,
        )


ground_truth_manager = GroundTruthStateManager()
