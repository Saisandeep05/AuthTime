"""
Ground Truth State Manager.

Maintains expected authorization state (Ground Truth GT) at any given timestamp T.
Compares intended access policy vs actual application authorization decisions.
"""

import threading
from typing import Dict, Any, List, Optional
from authtime.models.schemas import GroundTruthState, RoleEnum


class GroundTruthStateManager:
    def __init__(self):
        self._lock = threading.RLock()
        self.reset_to_defaults()

    def reset_to_defaults(self):
        with self._lock:
            # user_id -> role
            self._user_roles: Dict[str, str] = {
                "admin1": "Admin",
                "user1": "User",
                "guest1": "Guest",
                "svc1": "ServiceAccount",
            }
            # List of fault events: (timestamp_monotonic, fault_type, user_id, new_role)
            self._fault_history: List[dict] = []

    def record_fault_event(
        self,
        fault_type: str,
        user_id: str,
        timestamp_monotonic: float,
        new_role: Optional[str] = "User",
    ):
        with self._lock:
            self._fault_history.append({
                "timestamp_monotonic": timestamp_monotonic,
                "fault_type": fault_type,
                "user_id": user_id,
                "new_role": new_role,
            })
            # Update ground truth role effective at timestamp_monotonic
            if new_role:
                self._user_roles[user_id] = new_role

    def get_expected_role(self, user_id: str, timestamp_monotonic: float) -> str:
        """Determines expected role at timestamp T based on initial state and fault history."""
        with self._lock:
            # Find initial role
            current_role = "User"
            if user_id == "admin1":
                current_role = "Admin"
            elif user_id == "guest1":
                current_role = "Guest"
            elif user_id == "svc1":
                current_role = "ServiceAccount"

            # Apply faults up to timestamp_monotonic
            for fault in self._fault_history:
                if fault["user_id"] == user_id and fault["timestamp_monotonic"] <= timestamp_monotonic:
                    if fault["new_role"]:
                        current_role = fault["new_role"]

            return current_role

    def get_expected_decision(self, user_id: str, resource_path: str, timestamp_monotonic: float) -> str:
        """
        Evaluates Ground Truth decision ('ALLOW' vs 'DENY') for resource at timestamp T.
        """
        role = self.get_expected_role(user_id, timestamp_monotonic)

        if resource_path.startswith("/admin"):
            return "ALLOW" if role == "Admin" else "DENY"
        elif resource_path.startswith("/invoices"):
            return "ALLOW" if role in ("Admin", "User", "Guest", "ServiceAccount") else "DENY"

        return "DENY"

    def get_expected_state(self, user_id: str, resource_path: str, timestamp_monotonic: float) -> GroundTruthState:
        role_str = self.get_expected_role(user_id, timestamp_monotonic)
        try:
            role_enum = RoleEnum(role_str)
        except ValueError:
            role_enum = RoleEnum.USER

        decision = self.get_expected_decision(user_id, resource_path, timestamp_monotonic)

        return GroundTruthState(
            timestamp_monotonic=timestamp_monotonic,
            user_id=user_id,
            expected_role=role_enum,
            expected_permissions=["MANAGE_USERS"] if role_str == "Admin" else ["READ_INVOICE"],
            resource_path=resource_path,
            expected_decision=decision,
        )


# Global singleton instance
ground_truth_manager = GroundTruthStateManager()
