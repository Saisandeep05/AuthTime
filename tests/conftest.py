import sys
from pathlib import Path
import pytest

# Add root directory to sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from app.models.db import db
from app.cache.ttl_cache import auth_cache
from app.api.endpoints import audit_events


@pytest.fixture(autouse=True)
def reset_app_state_between_tests():
    """Ensure clean baseline state before every test run."""
    db.reset_to_defaults()
    auth_cache.clear()
    audit_events.clear()
    yield
    db.reset_to_defaults()
    auth_cache.clear()
    audit_events.clear()
