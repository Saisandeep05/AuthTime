"""
Unit tests for ExperimentController.aggregate_trial_statistics().

Validates multi-trial aggregation with all-uncensored, mixed censored/uncensored,
single-trial, and no-valid-trial scenarios.
"""

import statistics

import pytest
from authtime.controller.experiment import ExperimentController


class TestAggregateNoValidTrials:
    """When no trials pass baseline + cleanup, return empty result."""

    def test_empty_results_list(self):
        result = ExperimentController.aggregate_trial_statistics([])
        assert result["trial_count"] == 0
        assert "No valid trials" in result["message"]

    def test_failed_baseline_excluded(self, experiment_result_factory):
        """Trials that fail baseline should be excluded from aggregation."""
        failed = experiment_result_factory(baseline_passed=False)
        result = ExperimentController.aggregate_trial_statistics([failed])
        assert result["trial_count"] == 0

    def test_failed_cleanup_excluded(self, experiment_result_factory):
        """Trials with failed cleanup should be excluded from aggregation."""
        failed = experiment_result_factory(cleanup_status="FAILED")
        result = ExperimentController.aggregate_trial_statistics([failed])
        assert result["trial_count"] == 0

    def test_mixed_valid_and_invalid_counts_only_valid(self, experiment_result_factory):
        """Only baseline_passed=True AND cleanup_status=VERIFIED trials are counted."""
        valid = experiment_result_factory(
            experiment_id="valid", baseline_passed=True, cleanup_status="VERIFIED"
        )
        invalid1 = experiment_result_factory(
            experiment_id="bad-bl", baseline_passed=False, cleanup_status="VERIFIED"
        )
        invalid2 = experiment_result_factory(
            experiment_id="bad-cl", baseline_passed=True, cleanup_status="FAILED"
        )
        result = ExperimentController.aggregate_trial_statistics([valid, invalid1, invalid2])
        assert result["trial_count"] == 1


class TestAggregateAllUncensored:
    """All-uncensored scenario: ordinary statistics should be fully computed."""

    def test_mean_median_std_computed_correctly(self, experiment_result_factory):
        trials = [
            experiment_result_factory(
                experiment_id=f"unc-{i}",
                estimated_exposure_sec=exp,
                exposure_interval_min_sec=exp - 1.0,
                exposure_interval_max_sec=exp + 1.0,
                is_censored=False,
            )
            for i, exp in enumerate([4.0, 6.0, 8.0, 10.0])
        ]
        result = ExperimentController.aggregate_trial_statistics(trials)

        exposures = [4.0, 6.0, 8.0, 10.0]
        assert result["trial_count"] == 4
        assert result["uncensored_trial_count"] == 4
        assert result["censored_trial_count"] == 0
        assert result["mean_exposure_sec"] == statistics.mean(exposures)
        assert result["median_sec"] == statistics.median(exposures)
        assert result["std_dev_sec"] == pytest.approx(statistics.stdev(exposures))
        assert result["min_exposure_sec"] == 4.0
        assert result["max_exposure_sec"] == 10.0

    def test_single_trial_std_is_zero(self, experiment_result_factory):
        """A single trial should produce std_dev = 0.0."""
        trial = experiment_result_factory(
            experiment_id="single",
            estimated_exposure_sec=5.0,
            is_censored=False,
        )
        result = ExperimentController.aggregate_trial_statistics([trial])
        assert result["trial_count"] == 1
        assert result["std_dev_sec"] == 0.0
        assert result["mean_exposure_sec"] == 5.0
        assert result["median_sec"] == 5.0

    def test_two_trials_std_nonzero(self, experiment_result_factory):
        """Two different uncensored exposures should yield a non-zero std."""
        trials = [
            experiment_result_factory(experiment_id="t1", estimated_exposure_sec=2.0, is_censored=False),
            experiment_result_factory(experiment_id="t2", estimated_exposure_sec=8.0, is_censored=False),
        ]
        result = ExperimentController.aggregate_trial_statistics(trials)
        assert result["std_dev_sec"] > 0


class TestAggregateMixedCensored:
    """Mixed censored/uncensored scenario: mean and std must be suppressed."""

    def test_mean_suppressed_with_censored_data(self, experiment_result_factory):
        uncensored = experiment_result_factory(
            experiment_id="unc",
            estimated_exposure_sec=5.0,
            exposure_interval_min_sec=4.0,
            is_censored=False,
        )
        censored = experiment_result_factory(
            experiment_id="cen",
            estimated_exposure_sec=None,
            exposure_interval_min_sec=10.0,
            exposure_interval_max_sec=None,
            is_censored=True,
            measurement_status="CENSORED_LOWER_BOUND",
        )
        result = ExperimentController.aggregate_trial_statistics([uncensored, censored])

        assert result["trial_count"] == 2
        assert result["uncensored_trial_count"] == 1
        assert result["censored_trial_count"] == 1
        assert result["mean_exposure_sec"] is None  # Suppressed per censoring standards
        assert result["std_dev_sec"] is None  # Suppressed
        assert result["median_sec"] is not None  # Median uses lower bounds
        assert result["limited_sample_note"] is not None
        assert "NOT ESTIMABLE" in result["limited_sample_note"]

    def test_all_censored_suppresses_mean(self, experiment_result_factory):
        censored_trials = [
            experiment_result_factory(
                experiment_id=f"cen-{i}",
                estimated_exposure_sec=None,
                exposure_interval_min_sec=float(i * 5),
                exposure_interval_max_sec=None,
                is_censored=True,
                measurement_status="CENSORED_LOWER_BOUND",
            )
            for i in range(1, 4)
        ]
        result = ExperimentController.aggregate_trial_statistics(censored_trials)
        assert result["mean_exposure_sec"] is None
        assert result["std_dev_sec"] is None
        assert result["trial_count"] == 3


class TestAggregateSeverityScoring:
    """Verify severity score averaging across trials."""

    def test_severity_scores_averaged(self, experiment_result_factory):
        trials = [
            experiment_result_factory(experiment_id="s1", severity_score=4.0),
            experiment_result_factory(experiment_id="s2", severity_score=8.0),
            experiment_result_factory(experiment_id="s3", severity_score=6.0),
        ]
        result = ExperimentController.aggregate_trial_statistics(trials)
        assert result["mean_severity_score"] == pytest.approx(6.0)

    def test_single_trial_severity_equals_input(self, experiment_result_factory):
        trial = experiment_result_factory(experiment_id="ss", severity_score=7.5)
        result = ExperimentController.aggregate_trial_statistics([trial])
        assert result["mean_severity_score"] == 7.5


class TestAggregateLimitedSampleNote:
    """Verify that the limited_sample_note is set when N < 5 or censored data is present."""

    def test_note_present_when_fewer_than_five_uncensored(self, experiment_result_factory):
        """With fewer than 5 uncensored trials, note should be present."""
        trials = [
            experiment_result_factory(experiment_id=f"few-{i}", is_censored=False)
            for i in range(3)
        ]
        result = ExperimentController.aggregate_trial_statistics(trials)
        assert result["limited_sample_note"] is not None

    def test_note_present_when_censored_data_exists(self, experiment_result_factory):
        """When any censored data is present, note should be present."""
        # 6 uncensored + 1 censored
        uncensored = [
            experiment_result_factory(experiment_id=f"u-{i}", is_censored=False)
            for i in range(6)
        ]
        censored = [
            experiment_result_factory(
                experiment_id="c-0",
                is_censored=True,
                estimated_exposure_sec=None,
                exposure_interval_max_sec=None,
                measurement_status="CENSORED_LOWER_BOUND",
            )
        ]
        result = ExperimentController.aggregate_trial_statistics(uncensored + censored)
        assert result["limited_sample_note"] is not None
