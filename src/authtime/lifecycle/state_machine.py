"""
AuthTime Strict Lifecycle State Machine & Execution Invariant Engine.
Enforces legal state transitions and prevents reporting valid results from invalid lifecycle states.
"""

from enum import Enum
from typing import List, Optional, Tuple


class ExperimentState(str, Enum):
    CREATED = "CREATED"
    TARGET_VERIFIED = "TARGET_VERIFIED"
    BASELINE_VERIFIED = "BASELINE_VERIFIED"
    FAULT_INJECTED = "FAULT_INJECTED"
    PROBING = "PROBING"
    ANALYZED = "ANALYZED"
    CLEANUP = "CLEANUP"
    CLEAN_VERIFIED = "CLEAN_VERIFIED"
    VALID = "VALID"
    INVALID = "INVALID"


# Legal State Transitions
ALLOWED_TRANSITIONS = {
    ExperimentState.CREATED: {ExperimentState.TARGET_VERIFIED, ExperimentState.INVALID},
    ExperimentState.TARGET_VERIFIED: {ExperimentState.BASELINE_VERIFIED, ExperimentState.INVALID},
    ExperimentState.BASELINE_VERIFIED: {ExperimentState.FAULT_INJECTED, ExperimentState.INVALID},
    ExperimentState.FAULT_INJECTED: {ExperimentState.PROBING, ExperimentState.INVALID},
    ExperimentState.PROBING: {ExperimentState.ANALYZED, ExperimentState.INVALID},
    ExperimentState.ANALYZED: {ExperimentState.CLEANUP, ExperimentState.INVALID},
    ExperimentState.CLEANUP: {ExperimentState.CLEAN_VERIFIED, ExperimentState.INVALID},
    ExperimentState.CLEAN_VERIFIED: {ExperimentState.VALID, ExperimentState.INVALID},
    ExperimentState.VALID: set(),
    ExperimentState.INVALID: set(),
}


class ExperimentStateMachine:
    def __init__(self, experiment_id: str):
        self.experiment_id = experiment_id
        self._current_state: ExperimentState = ExperimentState.CREATED
        self._history: List[Tuple[ExperimentState, float, str]] = [(ExperimentState.CREATED, 0.0, "Experiment created")]
        self._failure_reason: Optional[str] = None

    @property
    def current_state(self) -> ExperimentState:
        return self._current_state

    @property
    def is_valid(self) -> bool:
        return self._current_state == ExperimentState.VALID

    @property
    def failure_reason(self) -> Optional[str]:
        return self._failure_reason

    def get_history_strings(self) -> List[str]:
        return [s.value for s, _, _ in self._history]

    def transition_to(self, next_state: ExperimentState, timestamp_monotonic: float, note: str = "") -> bool:
        """
        Transitions to next_state if allowed by strict lifecycle transition invariants.
        Returns True if successful, False if invalid transition.
        """
        if next_state not in ALLOWED_TRANSITIONS.get(self._current_state, set()):
            self._failure_reason = f"ILLEGAL_TRANSITION: Cannot jump from {self._current_state.value} to {next_state.value}"
            self._current_state = ExperimentState.INVALID
            self._history.append((ExperimentState.INVALID, timestamp_monotonic, self._failure_reason))
            return False

        self._current_state = next_state
        self._history.append((next_state, timestamp_monotonic, note))
        return True

    def mark_invalid(self, timestamp_monotonic: float, reason: str):
        """
        Marks experiment as INVALID due to baseline, execution, or cleanup failure.
        """
        self._failure_reason = reason
        self._current_state = ExperimentState.INVALID
        self._history.append((ExperimentState.INVALID, timestamp_monotonic, f"INVALID: {reason}"))
