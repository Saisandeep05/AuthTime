"""
Unit tests for Scenario Generator and Cross-User Isolation Scenarios.
"""

from authtime.scenarios.generator import ScenarioGenerator


def test_single_fault_scenario_generation():
    scen = ScenarioGenerator.generate_single_fault_scenario("stale_cache", time_scale_factor=0.5)

    assert scen.scenario_id == "scen-stale_cache-admin1"
    assert len(scen.probes) == 5
    # Scaled offsets: [0.0, 0.5, 2.5, 15.0, 30.0]
    assert scen.probes[1].offset_seconds == 0.5
    assert scen.probes[4].offset_seconds == 30.0


def test_cross_user_isolation_scenario_generation():
    scen = ScenarioGenerator.generate_cross_user_isolation_scenario("admin1", "user1")

    assert scen.fault_type == "cross_user_isolation"
    assert scen.secondary_user_id == "user1"
    assert len(scen.probes) == 10  # 5 offsets * 2 users

    # Check alternating user probes
    assert scen.probes[0].user_id == "admin1"
    assert scen.probes[0].expected_decision == "DENY"

    assert scen.probes[1].user_id == "user1"
    assert scen.probes[1].expected_decision == "ALLOW"
