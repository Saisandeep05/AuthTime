"""
Unit tests for censoring-aware statistical analysis.

Validates the Kaplan-Meier survival estimator, lower-bound median calculation,
and uncertainty interval formatting against known inputs and edge cases.
"""

import pytest
from authtime.statistics.censoring import calculate_kaplan_meier_survival, format_uncertainty_interval


class TestKaplanMeierEmpty:
    """Edge case: empty input should return safe defaults."""

    def test_empty_input_returns_no_data(self):
        result = calculate_kaplan_meier_survival([])
        assert result["survival_curve"] == []
        assert result["median_exposure_sec"] is None
        assert "No trial events" in result["note"]


class TestKaplanMeierAllUncensored:
    """When all observations are uncensored, ordinary mean should be estimable."""

    def test_three_uncensored_trials(self):
        trials = [
            {"exposure_interval_min_sec": 2.0, "estimated_exposure_sec": 2.5, "is_censored": False},
            {"exposure_interval_min_sec": 4.0, "estimated_exposure_sec": 4.5, "is_censored": False},
            {"exposure_interval_min_sec": 6.0, "estimated_exposure_sec": 6.5, "is_censored": False},
        ]
        result = calculate_kaplan_meier_survival(trials)

        assert result["trial_count"] == 3
        assert result["uncensored_count"] == 3
        assert result["censored_count"] == 0

        # Mean should be (2.5 + 4.5 + 6.5) / 3 = 4.5
        assert result["mean_exposure_sec"] == 4.5

        # Note should confirm mean is estimable
        assert "estimable" in result["note"].lower()

    def test_survival_curve_has_correct_step_count(self):
        """Each uncensored event produces one step in the survival curve."""
        trials = [
            {"exposure_interval_min_sec": 1.0, "estimated_exposure_sec": 1.0, "is_censored": False},
            {"exposure_interval_min_sec": 3.0, "estimated_exposure_sec": 3.0, "is_censored": False},
        ]
        result = calculate_kaplan_meier_survival(trials)
        assert len(result["kaplan_meier_curve"]) == 2

    def test_survival_probability_is_monotonically_decreasing(self):
        """S(t) must never increase across the survival curve."""
        trials = [
            {"exposure_interval_min_sec": 1.0, "estimated_exposure_sec": 1.0, "is_censored": False},
            {"exposure_interval_min_sec": 2.0, "estimated_exposure_sec": 2.0, "is_censored": False},
            {"exposure_interval_min_sec": 5.0, "estimated_exposure_sec": 5.0, "is_censored": False},
            {"exposure_interval_min_sec": 8.0, "estimated_exposure_sec": 8.0, "is_censored": False},
        ]
        result = calculate_kaplan_meier_survival(trials)
        curve = result["kaplan_meier_curve"]
        for i in range(1, len(curve)):
            assert curve[i]["survival_probability"] <= curve[i - 1]["survival_probability"], \
                f"S(t) increased at step {i}: {curve[i-1]['survival_probability']} -> {curve[i]['survival_probability']}"

    def test_final_survival_probability_reaches_zero_all_uncensored(self):
        """When all observations are uncensored, S(t_max) should reach 0."""
        trials = [
            {"exposure_interval_min_sec": 1.0, "estimated_exposure_sec": 1.0, "is_censored": False},
            {"exposure_interval_min_sec": 2.0, "estimated_exposure_sec": 2.0, "is_censored": False},
            {"exposure_interval_min_sec": 3.0, "estimated_exposure_sec": 3.0, "is_censored": False},
        ]
        result = calculate_kaplan_meier_survival(trials)
        curve = result["kaplan_meier_curve"]
        assert len(curve) == 3
        assert curve[-1]["survival_probability"] == 0.0

    def test_single_uncensored_trial(self):
        """A single uncensored trial should produce one curve step and estimable mean."""
        trials = [
            {"exposure_interval_min_sec": 5.0, "estimated_exposure_sec": 5.5, "is_censored": False},
        ]
        result = calculate_kaplan_meier_survival(trials)
        assert result["trial_count"] == 1
        assert result["uncensored_count"] == 1
        assert result["mean_exposure_sec"] == 5.5
        assert len(result["kaplan_meier_curve"]) == 1
        assert result["kaplan_meier_curve"][0]["survival_probability"] == 0.0


class TestKaplanMeierAllCensored:
    """When all observations are censored, mean must be suppressed (NOT ESTIMABLE)."""

    def test_all_censored_suppresses_mean(self):
        trials = [
            {"exposure_interval_min_sec": 10.0, "is_censored": True},
            {"exposure_interval_min_sec": 20.0, "is_censored": True},
        ]
        result = calculate_kaplan_meier_survival(trials)

        assert result["trial_count"] == 2
        assert result["censored_count"] == 2
        assert result["uncensored_count"] == 0
        assert result["mean_exposure_sec"] is None
        assert "NOT ESTIMABLE" in result["note"]

    def test_all_censored_produces_no_curve_steps(self):
        """Censored observations do not produce events in the survival curve."""
        trials = [
            {"exposure_interval_min_sec": 5.0, "is_censored": True},
            {"exposure_interval_min_sec": 15.0, "is_censored": True},
        ]
        result = calculate_kaplan_meier_survival(trials)
        assert len(result["kaplan_meier_curve"]) == 0


class TestKaplanMeierMixed:
    """Mixed censored/uncensored data: mean suppressed, KM curve present."""

    def test_mixed_suppresses_mean_and_produces_curve(self):
        trials = [
            {"exposure_interval_min_sec": 2.0, "estimated_exposure_sec": 2.5, "is_censored": False},
            {"exposure_interval_min_sec": 8.0, "is_censored": True},
            {"exposure_interval_min_sec": 5.0, "estimated_exposure_sec": 5.5, "is_censored": False},
        ]
        result = calculate_kaplan_meier_survival(trials)

        assert result["trial_count"] == 3
        assert result["uncensored_count"] == 2
        assert result["censored_count"] == 1
        # Mean must be suppressed because censored data is present
        assert result["mean_exposure_sec"] is None
        assert "NOT ESTIMABLE" in result["note"]
        # Curve steps should only be from uncensored observations
        assert len(result["kaplan_meier_curve"]) == 2

    def test_lower_bound_median_uses_sorted_minimums(self):
        """Lower-bound median should be the median of exposure_interval_min_sec values."""
        trials = [
            {"exposure_interval_min_sec": 1.0, "estimated_exposure_sec": 1.0, "is_censored": False},
            {"exposure_interval_min_sec": 3.0, "is_censored": True},
            {"exposure_interval_min_sec": 5.0, "estimated_exposure_sec": 5.0, "is_censored": False},
        ]
        result = calculate_kaplan_meier_survival(trials)
        # Sorted mins: [1.0, 3.0, 5.0], median index = 3 // 2 = 1 → 3.0
        assert result["lower_bound_median_sec"] == 3.0


class TestKaplanMeierNAtRisk:
    """Verify n_at_risk counts are correctly tracked in the survival curve."""

    def test_n_at_risk_decreases_monotonically(self):
        trials = [
            {"exposure_interval_min_sec": 1.0, "estimated_exposure_sec": 1.0, "is_censored": False},
            {"exposure_interval_min_sec": 2.0, "estimated_exposure_sec": 2.0, "is_censored": False},
            {"exposure_interval_min_sec": 3.0, "estimated_exposure_sec": 3.0, "is_censored": False},
        ]
        result = calculate_kaplan_meier_survival(trials)
        curve = result["kaplan_meier_curve"]
        n_at_risk_values = [step["n_at_risk"] for step in curve]
        for i in range(1, len(n_at_risk_values)):
            assert n_at_risk_values[i] < n_at_risk_values[i - 1]

    def test_first_step_n_at_risk_equals_total(self):
        trials = [
            {"exposure_interval_min_sec": 1.0, "estimated_exposure_sec": 1.0, "is_censored": False},
            {"exposure_interval_min_sec": 5.0, "is_censored": True},
        ]
        result = calculate_kaplan_meier_survival(trials)
        curve = result["kaplan_meier_curve"]
        assert curve[0]["n_at_risk"] == 2  # Total trials


class TestFormatUncertaintyInterval:
    """Tests for format_uncertainty_interval() output formatting."""

    def test_uncensored_interval_formatting(self):
        """Uncensored data should show midpoint ± precision with full interval."""
        result = format_uncertainty_interval(
            exposure_min_sec=5.0,
            exposure_max_sec=10.0,
            precision_sec=2.5,
            is_censored=False,
        )
        assert "7.50s" in result  # Midpoint (5+10)/2
        assert "± 2.50s" in result
        assert "[5.00s, 10.00s]" in result

    def test_censored_interval_formatting(self):
        """Censored data should show conservative lower bound."""
        result = format_uncertainty_interval(
            exposure_min_sec=12.0,
            exposure_max_sec=None,
            precision_sec=None,
            is_censored=True,
        )
        assert "≥ 12.00s" in result
        assert "Conservative Lower Bound" in result

    def test_missing_max_treated_as_censored(self):
        """If exposure_max_sec is None, format as lower bound even if is_censored=False."""
        result = format_uncertainty_interval(
            exposure_min_sec=8.0,
            exposure_max_sec=None,
            precision_sec=None,
            is_censored=False,
        )
        assert "≥ 8.00s" in result
        assert "Conservative Lower Bound" in result

    def test_missing_precision_treated_as_censored(self):
        """If precision_sec is None, format as lower bound."""
        result = format_uncertainty_interval(
            exposure_min_sec=3.0,
            exposure_max_sec=6.0,
            precision_sec=None,
            is_censored=False,
        )
        assert "≥ 3.00s" in result

    def test_zero_exposure_formats_correctly(self):
        """Zero exposure should format without error."""
        result = format_uncertainty_interval(
            exposure_min_sec=0.0,
            exposure_max_sec=0.0,
            precision_sec=0.0,
            is_censored=False,
        )
        assert "0.00s" in result
