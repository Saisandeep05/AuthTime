"""
Unit tests for ExperimentStateMachine lifecycle transition enforcement.

Validates that the state machine correctly enforces the legal transition graph,
rejects illegal transitions, records history accurately, and propagates failure reasons.
"""

import pytest
from authtime.lifecycle.state_machine import ExperimentStateMachine, ExperimentState, ALLOWED_TRANSITIONS


class TestLegalTransitions:
    """Verify the happy path: full legal lifecycle CREATED → ... → VALID."""

    def test_full_legal_lifecycle_reaches_valid(self):
        """The complete legal transition sequence should reach VALID state."""
        sm = ExperimentStateMachine("exp-happy-path")

        legal_sequence = [
            (ExperimentState.TARGET_VERIFIED, 1.0, "Target OK"),
            (ExperimentState.BASELINE_VERIFIED, 2.0, "Baseline OK"),
            (ExperimentState.FAULT_INJECTED, 3.0, "Fault injected"),
            (ExperimentState.PROBING, 4.0, "Probing started"),
            (ExperimentState.ANALYZED, 5.0, "Analysis complete"),
            (ExperimentState.CLEANUP, 6.0, "Cleanup started"),
            (ExperimentState.CLEAN_VERIFIED, 7.0, "Cleanup verified"),
            (ExperimentState.VALID, 8.0, "Experiment valid"),
        ]

        for state, ts, note in legal_sequence:
            result = sm.transition_to(state, ts, note)
            assert result is True, f"Legal transition to {state.value} should succeed"
            assert sm.current_state == state

        assert sm.is_valid is True
        assert sm.failure_reason is None

    def test_initial_state_is_created(self):
        """A newly created state machine should be in CREATED state."""
        sm = ExperimentStateMachine("exp-init")
        assert sm.current_state == ExperimentState.CREATED
        assert sm.is_valid is False
        assert sm.failure_reason is None

    def test_each_legal_forward_transition_succeeds(self):
        """Verify every edge in the ALLOWED_TRANSITIONS graph returns True."""
        # Test each transition pair individually
        forward_edges = [
            (ExperimentState.CREATED, ExperimentState.TARGET_VERIFIED),
            (ExperimentState.TARGET_VERIFIED, ExperimentState.BASELINE_VERIFIED),
            (ExperimentState.BASELINE_VERIFIED, ExperimentState.FAULT_INJECTED),
            (ExperimentState.FAULT_INJECTED, ExperimentState.PROBING),
            (ExperimentState.PROBING, ExperimentState.ANALYZED),
            (ExperimentState.ANALYZED, ExperimentState.CLEANUP),
            (ExperimentState.CLEANUP, ExperimentState.CLEAN_VERIFIED),
            (ExperimentState.CLEAN_VERIFIED, ExperimentState.VALID),
        ]
        sm = ExperimentStateMachine("exp-edges")
        for _, next_state in forward_edges:
            assert sm.transition_to(next_state, 1.0) is True


class TestIllegalTransitions:
    """Verify that illegal state transitions are rejected and trigger INVALID."""

    def test_skip_state_is_rejected(self):
        """Skipping a state (CREATED → PROBING) should fail and mark INVALID."""
        sm = ExperimentStateMachine("exp-skip")
        result = sm.transition_to(ExperimentState.PROBING, 1.0, "Attempt skip")
        assert result is False
        assert sm.current_state == ExperimentState.INVALID
        assert sm.failure_reason is not None
        assert "ILLEGAL_TRANSITION" in sm.failure_reason
        assert "CREATED" in sm.failure_reason
        assert "PROBING" in sm.failure_reason

    def test_backward_transition_is_rejected(self):
        """Going backwards (TARGET_VERIFIED → CREATED) should fail."""
        sm = ExperimentStateMachine("exp-backward")
        sm.transition_to(ExperimentState.TARGET_VERIFIED, 1.0)
        result = sm.transition_to(ExperimentState.CREATED, 2.0)
        assert result is False
        assert sm.current_state == ExperimentState.INVALID

    def test_self_transition_is_rejected(self):
        """Transitioning to the same state (CREATED → CREATED) should fail."""
        sm = ExperimentStateMachine("exp-self")
        result = sm.transition_to(ExperimentState.CREATED, 1.0)
        assert result is False
        assert sm.current_state == ExperimentState.INVALID

    @pytest.mark.parametrize("initial_advance_to", [
        ExperimentState.TARGET_VERIFIED,
        ExperimentState.BASELINE_VERIFIED,
        ExperimentState.FAULT_INJECTED,
        ExperimentState.PROBING,
        ExperimentState.ANALYZED,
    ])
    def test_direct_jump_to_valid_is_rejected(self, initial_advance_to):
        """Jumping directly to VALID from any non-CLEAN_VERIFIED state should fail."""
        sm = ExperimentStateMachine("exp-jump-valid")
        # Advance to the given state through legal transitions
        legal_path = [
            ExperimentState.TARGET_VERIFIED,
            ExperimentState.BASELINE_VERIFIED,
            ExperimentState.FAULT_INJECTED,
            ExperimentState.PROBING,
            ExperimentState.ANALYZED,
        ]
        for state in legal_path:
            sm.transition_to(state, 1.0)
            if state == initial_advance_to:
                break

        result = sm.transition_to(ExperimentState.VALID, 2.0)
        assert result is False
        assert sm.current_state == ExperimentState.INVALID


class TestTerminalStates:
    """Verify that VALID and INVALID are terminal: no further transitions allowed."""

    def test_valid_state_accepts_no_transitions(self):
        """After reaching VALID, all further transitions should be rejected."""
        sm = ExperimentStateMachine("exp-terminal-valid")
        # Advance to VALID
        for state in [
            ExperimentState.TARGET_VERIFIED, ExperimentState.BASELINE_VERIFIED,
            ExperimentState.FAULT_INJECTED, ExperimentState.PROBING,
            ExperimentState.ANALYZED, ExperimentState.CLEANUP,
            ExperimentState.CLEAN_VERIFIED, ExperimentState.VALID,
        ]:
            sm.transition_to(state, 1.0)

        assert sm.current_state == ExperimentState.VALID
        # Any transition from VALID should fail
        for target in ExperimentState:
            if target == ExperimentState.VALID:
                continue
            result = sm.transition_to(target, 2.0)
            assert result is False

    def test_invalid_state_accepts_no_transitions(self):
        """After reaching INVALID, all further transitions should be rejected."""
        sm = ExperimentStateMachine("exp-terminal-invalid")
        sm.mark_invalid(1.0, "Test failure")
        assert sm.current_state == ExperimentState.INVALID

        for target in ExperimentState:
            if target == ExperimentState.INVALID:
                continue
            result = sm.transition_to(target, 2.0)
            assert result is False

    def test_allowed_transitions_table_completeness(self):
        """Every ExperimentState must have an entry in ALLOWED_TRANSITIONS."""
        for state in ExperimentState:
            assert state in ALLOWED_TRANSITIONS, f"Missing ALLOWED_TRANSITIONS entry for {state.value}"


class TestMarkInvalid:
    """Verify mark_invalid() behavior from various states."""

    def test_mark_invalid_from_created(self):
        sm = ExperimentStateMachine("exp-mark-1")
        sm.mark_invalid(1.0, "Baseline failed")
        assert sm.current_state == ExperimentState.INVALID
        assert sm.failure_reason == "Baseline failed"
        assert sm.is_valid is False

    def test_mark_invalid_from_mid_lifecycle(self):
        sm = ExperimentStateMachine("exp-mark-2")
        sm.transition_to(ExperimentState.TARGET_VERIFIED, 1.0)
        sm.transition_to(ExperimentState.BASELINE_VERIFIED, 2.0)
        sm.transition_to(ExperimentState.FAULT_INJECTED, 3.0)
        sm.mark_invalid(4.0, "Probe timeout")
        assert sm.current_state == ExperimentState.INVALID
        assert sm.failure_reason == "Probe timeout"

    def test_mark_invalid_records_history_entry(self):
        sm = ExperimentStateMachine("exp-mark-3")
        sm.mark_invalid(5.0, "Cleanup failed")
        history = sm.get_history_strings()
        assert "INVALID" in history


class TestHistoryRecording:
    """Verify that get_history_strings() accurately records the state sequence."""

    def test_initial_history_contains_created(self):
        sm = ExperimentStateMachine("exp-hist-1")
        history = sm.get_history_strings()
        assert history == ["CREATED"]

    def test_history_records_all_transitions(self):
        sm = ExperimentStateMachine("exp-hist-2")
        sm.transition_to(ExperimentState.TARGET_VERIFIED, 1.0)
        sm.transition_to(ExperimentState.BASELINE_VERIFIED, 2.0)
        history = sm.get_history_strings()
        assert history == ["CREATED", "TARGET_VERIFIED", "BASELINE_VERIFIED"]

    def test_history_records_invalid_on_illegal_transition(self):
        sm = ExperimentStateMachine("exp-hist-3")
        sm.transition_to(ExperimentState.PROBING, 1.0)  # Illegal
        history = sm.get_history_strings()
        assert history == ["CREATED", "INVALID"]

    def test_history_length_matches_transition_count(self):
        sm = ExperimentStateMachine("exp-hist-4")
        sm.transition_to(ExperimentState.TARGET_VERIFIED, 1.0)
        sm.transition_to(ExperimentState.BASELINE_VERIFIED, 2.0)
        sm.transition_to(ExperimentState.FAULT_INJECTED, 3.0)
        # 1 initial + 3 transitions = 4
        assert len(sm.get_history_strings()) == 4


class TestTransitionToInvalidFromEveryState:
    """Every non-terminal state should allow transition to INVALID."""

    @pytest.mark.parametrize("source_state,advance_path", [
        (ExperimentState.CREATED, []),
        (ExperimentState.TARGET_VERIFIED, [ExperimentState.TARGET_VERIFIED]),
        (ExperimentState.BASELINE_VERIFIED, [ExperimentState.TARGET_VERIFIED, ExperimentState.BASELINE_VERIFIED]),
        (ExperimentState.FAULT_INJECTED, [ExperimentState.TARGET_VERIFIED, ExperimentState.BASELINE_VERIFIED, ExperimentState.FAULT_INJECTED]),
        (ExperimentState.PROBING, [ExperimentState.TARGET_VERIFIED, ExperimentState.BASELINE_VERIFIED, ExperimentState.FAULT_INJECTED, ExperimentState.PROBING]),
        (ExperimentState.ANALYZED, [ExperimentState.TARGET_VERIFIED, ExperimentState.BASELINE_VERIFIED, ExperimentState.FAULT_INJECTED, ExperimentState.PROBING, ExperimentState.ANALYZED]),
        (ExperimentState.CLEANUP, [ExperimentState.TARGET_VERIFIED, ExperimentState.BASELINE_VERIFIED, ExperimentState.FAULT_INJECTED, ExperimentState.PROBING, ExperimentState.ANALYZED, ExperimentState.CLEANUP]),
        (ExperimentState.CLEAN_VERIFIED, [ExperimentState.TARGET_VERIFIED, ExperimentState.BASELINE_VERIFIED, ExperimentState.FAULT_INJECTED, ExperimentState.PROBING, ExperimentState.ANALYZED, ExperimentState.CLEANUP, ExperimentState.CLEAN_VERIFIED]),
    ])
    def test_transition_to_invalid_succeeds(self, source_state, advance_path):
        sm = ExperimentStateMachine("exp-to-invalid")
        for state in advance_path:
            sm.transition_to(state, 1.0)
        assert sm.current_state == source_state
        result = sm.transition_to(ExperimentState.INVALID, 2.0)
        assert result is True
        assert sm.current_state == ExperimentState.INVALID
