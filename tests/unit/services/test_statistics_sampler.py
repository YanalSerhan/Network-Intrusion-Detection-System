"""Tests for deriving a throughput rate from successive counter samples."""



from network_defender.services.statistics_sampler import StatisticsSampler

# --------------------------------------------------------------------------
# Throughput sampling
# --------------------------------------------------------------------------


def test_first_sample_has_no_rate_to_report() -> None:
    """There is no interval to divide by yet."""
    assert StatisticsSampler().sample(1_000, now=100.0) == 0.0


def test_rate_is_derived_from_the_delta() -> None:
    sampler = StatisticsSampler()
    sampler.sample(1_000, now=100.0)

    # 500 more packets over 10 seconds.
    assert sampler.sample(1_500, now=110.0) == 50.0


def test_consecutive_samples_track_a_changing_rate() -> None:
    sampler = StatisticsSampler()
    sampler.sample(0, now=0.0)

    assert sampler.sample(100, now=1.0) == 100.0
    assert sampler.sample(400, now=2.0) == 300.0
    assert sampler.sample(400, now=3.0) == 0.0  # traffic stopped


def test_counter_reset_does_not_produce_a_negative_rate() -> None:
    """Capture restarting sets the cumulative counter back to zero."""
    sampler = StatisticsSampler()
    sampler.sample(5_000, now=100.0)

    assert sampler.sample(10, now=110.0) == 0.0
    # The next sample uses the post-reset value as its baseline.
    assert sampler.sample(110, now=111.0) == 100.0


def test_zero_elapsed_time_does_not_divide_by_zero() -> None:
    sampler = StatisticsSampler()
    sampler.sample(100, now=50.0)
    assert sampler.sample(200, now=50.0) == 0.0


def test_reset_starts_a_new_baseline() -> None:
    sampler = StatisticsSampler()
    sampler.sample(1_000, now=100.0)
    sampler.reset()
    assert sampler.sample(2_000, now=110.0) == 0.0
