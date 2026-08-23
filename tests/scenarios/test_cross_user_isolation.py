"""
Scenario tests for Cross-User Isolation.
"""

from authtime.scenarios.generator import ScenarioGenerator


def test_cross_user_scenario_generation():
    scen = ScenarioGenerator.generate_cross_user_isolation_scenario(
        user_a_id="admin1", user_b_id="user1", time_scale_factor=0.1
    )

    assert scen.fault_type == "cross_user_isolation"
    assert scen.target_user_id == "admin1"
    assert scen.secondary_user_id == "user1"
    assert len(scen.probes) == 10  # 5 coarse offsets x 2 users
    assert scen.probes[0].user_id == "admin1"
    assert scen.probes[1].user_id == "user1"
    assert scen.probes[1].expected_decision == "ALLOW"
