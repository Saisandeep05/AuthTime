"""
In-Memory User Repository and Application DB State.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel


class UserRecord(BaseModel):
    user_id: str
    username: str
    role: str
    is_active: bool = True


class InMemoryDB:
    def __init__(self):
        self.users: Dict[str, UserRecord] = {}
        self.reset_to_defaults()

    def reset_to_defaults(self):
        self.users = {
            "admin1": UserRecord(user_id="admin1", username="alice", role="Admin"),
            "user1": UserRecord(user_id="user1", username="bob", role="User"),
            "guest1": UserRecord(user_id="guest1", username="charlie", role="Guest"),
            "svc1": UserRecord(user_id="svc1", username="bot", role="ServiceAccount"),
        }

    def get_user(self, user_id: str) -> Optional[UserRecord]:
        return self.users.get(user_id)

    def update_role(self, user_id: str, new_role: str) -> bool:
        if user_id in self.users:
            self.users[user_id].role = new_role
            return True
        return False


db = InMemoryDB()
