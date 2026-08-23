"""
Scenario Generator & Experiment Matrix Engine.
Includes Positive Control (known vulnerable) and Negative Control (known safe) scenario generators.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ScenarioProbeSpec(BaseModel):
    probe_index: int
    offset_seconds: float
    user_id: str
    resource_path: str
    expected_decision: str  # "ALLOW" or "DENY"


class Scenario(BaseModel):
    scenario_id: str
    fault_type: str
    target_user_id: str
    secondary_user_id: Optional[str] = None
    resource_path: str
    probes: List[ScenarioProbeSpec]
    time_scale_factor: float = 1.0
    is_positive_control: bool = False
    is_negative_control: bool = False


class ScenarioGenerator:
    DEFAULT_CACHE_OFFSETS = [0.0, 1.0, 5.0, 30.0, 60.0]
    DEFAULT_TOKEN_OFFSETS = [0.0, 1.0, 5.0, 30.0, 100.0, 300.0]

    @classmethod
    def generate_single_fault_scenario(
        cls,
        fault_type: str,
        target_user_id: str = "admin1",
        resource_path: str = "/admin/users",
        coarse_offsets: Optional[List[float]] = None,
        time_scale_factor: float = 1.0,
    ) -> Scenario:
        if coarse_offsets is not None:
            offsets = coarse_offsets
        elif fault_type == "token_expiry":
            offsets = cls.DEFAULT_TOKEN_OFFSETS
        else:
            offsets = cls.DEFAULT_CACHE_OFFSETS

        scaled_offsets = [o * time_scale_factor for o in offsets]

        probes = []
        for i, offset in enumerate(scaled_offsets):
            probes.append(
                ScenarioProbeSpec(
                    probe_index=i,
                    offset_seconds=offset,
                    user_id=target_user_id,
                    resource_path=resource_path,
                    expected_decision="DENY" if offset >= 0 else "ALLOW",
                )
            )

        return Scenario(
            scenario_id=f"scen-{fault_type}-{target_user_id}",
            fault_type=fault_type,
            target_user_id=target_user_id,
            resource_path=resource_path,
            probes=probes,
            time_scale_factor=time_scale_factor,
        )

    @classmethod
    def generate_positive_control_scenario(
        cls,
        target_user_id: str = "admin1",
        time_scale_factor: float = 1.0,
    ) -> Scenario:
        """
        Positive Control Scenario: Known vulnerable stale authorization cache configuration.
        Expected: Detector MUST observe exposure window > 0.
        """
        scen = cls.generate_single_fault_scenario(
            fault_type="stale_cache",
            target_user_id=target_user_id,
            time_scale_factor=time_scale_factor,
        )
        scen.scenario_id = f"pos-control-stale_cache-{target_user_id}"
        scen.is_positive_control = True
        return scen

    @classmethod
    def generate_negative_control_scenario(
        cls,
        target_user_id: str = "admin1",
        time_scale_factor: float = 1.0,
    ) -> Scenario:
        """
        Negative Control Scenario: Known safe immediate role revocation without cache staleness.
        Expected: Detector MUST observe zero exposure window (exposure == 0.0s).
        """
        scen = cls.generate_single_fault_scenario(
            fault_type="role_revocation",
            target_user_id=target_user_id,
            time_scale_factor=time_scale_factor,
        )
        scen.scenario_id = f"neg-control-immediate_revocation-{target_user_id}"
        scen.is_negative_control = True
        return scen

    @classmethod
    def generate_cross_user_isolation_scenario(
        cls,
        user_a_id: str = "admin1",
        user_b_id: str = "user1",
        user_a_resource: str = "/admin/users",
        user_b_resource: str = "/invoices/1",
        coarse_offsets: Optional[List[float]] = None,
        time_scale_factor: float = 1.0,
    ) -> Scenario:
        offsets = coarse_offsets if coarse_offsets is not None else cls.DEFAULT_CACHE_OFFSETS
        scaled_offsets = [o * time_scale_factor for o in offsets]

        probes = []
        probe_idx = 0
        for offset in scaled_offsets:
            probes.append(
                ScenarioProbeSpec(
                    probe_index=probe_idx,
                    offset_seconds=offset,
                    user_id=user_a_id,
                    resource_path=user_a_resource,
                    expected_decision="DENY",
                )
            )
            probe_idx += 1

            probes.append(
                ScenarioProbeSpec(
                    probe_index=probe_idx,
                    offset_seconds=offset,
                    user_id=user_b_id,
                    resource_path=user_a_resource,
                    expected_decision="DENY",
                )
            )
            probe_idx += 1

        return Scenario(
            scenario_id=f"scen-cross_user-{user_a_id}-{user_b_id}",
            fault_type="cross_user_isolation",
            target_user_id=user_a_id,
            secondary_user_id=user_b_id,
            resource_path=user_a_resource,
            probes=probes,
            time_scale_factor=time_scale_factor,
        )

    @classmethod
    def generate_distributed_lab_scenario(
        cls,
        fault_type: str = "DELAYED_INVALIDATION",
        target_user_id: str = "admin1",
        resource_path: str = "/admin/users",
        time_scale_factor: float = 1.0,
    ) -> Scenario:
        """
        Generates distributed multi-replica authorization validation laboratory scenario.
        Scenarios: 'NO_FAULT', 'STALE_CACHE', 'DELAYED_INVALIDATION', 'PARTIAL_PROPAGATION', 'DROPPED_EVENT', 'REDIS_UNAVAILABLE'
        """
        scen = cls.generate_single_fault_scenario(
            fault_type=fault_type.lower(),
            target_user_id=target_user_id,
            resource_path=resource_path,
            time_scale_factor=time_scale_factor,
        )
        scen.scenario_id = f"dist-lab-{fault_type.lower()}-{target_user_id}"
        return scen

    @classmethod
    def generate_all_distributed_lab_scenarios(
        cls,
        target_user_id: str = "admin1",
    ) -> List[Scenario]:
        """Returns suite of all 6 real-world distributed authorization laboratory scenarios."""
        fault_types = [
            "NO_FAULT",
            "STALE_CACHE",
            "DELAYED_INVALIDATION",
            "PARTIAL_PROPAGATION",
            "DROPPED_EVENT",
            "REDIS_UNAVAILABLE",
        ]
        return [
            cls.generate_distributed_lab_scenario(
                fault_type=ft,
                target_user_id=target_user_id,
            )
            for ft in fault_types
        ]

