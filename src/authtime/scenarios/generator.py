"""
Scenario Generator & Experiment Matrix Engine.
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
                    resource_path=user_a_resource,  # Probes protected admin endpoint!
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
