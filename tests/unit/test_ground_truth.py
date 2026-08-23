"""
Unit tests for Ground Truth State Manager.
"""

from authtime.ground_truth.manager import GroundTruthStateManager, RoleEnum


def test_ground_truth_initial_states():
    gt = GroundTruthStateManager()

    assert gt.get_expected_role("admin1", 10.0) == "Admin"
    assert gt.get_expected_decision("admin1", "/admin/users", 10.0) == "ALLOW"

    assert gt.get_expected_role("user1", 10.0) == "User"
    assert gt.get_expected_decision("user1", "/admin/users", 10.0) == "DENY"
    assert gt.get_expected_decision("user1", "/invoices/1", 10.0) == "ALLOW"


def test_ground_truth_fault_recording():
    gt = GroundTruthStateManager()

    # Before fault at T=100s
    assert gt.get_expected_role("admin1", 50.0) == "Admin"
    assert gt.get_expected_decision("admin1", "/admin/users", 50.0) == "ALLOW"

    # Record role revocation fault at T=100s
    gt.record_fault_event("role_revocation", "admin1", 100.0, new_role="User")

    # Probe before T=100s should still expect Admin / ALLOW
    assert gt.get_expected_role("admin1", 99.9) == "Admin"
    assert gt.get_expected_decision("admin1", "/admin/users", 99.9) == "ALLOW"

    # Probe at or after T=100s should expect User / DENY
    assert gt.get_expected_role("admin1", 100.0) == "User"
    assert gt.get_expected_decision("admin1", "/admin/users", 100.0) == "DENY"

    state = gt.get_expected_state("admin1", "/admin/users", 100.5)
    assert state.expected_role == RoleEnum.USER
    assert state.expected_decision == "DENY"
