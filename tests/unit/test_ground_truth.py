"""
Unit tests for GroundTruthStateManager.
"""

from authtime.ground_truth.manager import GroundTruthStateManager


def test_ground_truth_pre_and_post_fault():
    gt = GroundTruthStateManager()
    gt.reset_to_defaults()

    # Pre-fault decision for admin1 on /admin/users should be ALLOW
    assert gt.get_expected_decision("admin1", "/admin/users", 10.0) == "ALLOW"

    # Record fault at t=20.0 (revokes admin1 to User)
    gt.record_fault_event("stale_cache", "admin1", timestamp_monotonic=20.0, new_role="User")

    # At t=15.0 (pre-fault), decision should still be ALLOW
    assert gt.get_expected_decision("admin1", "/admin/users", 15.0) == "ALLOW"

    # At t=20.1 (post-fault), decision should be DENY
    assert gt.get_expected_decision("admin1", "/admin/users", 20.1) == "DENY"
