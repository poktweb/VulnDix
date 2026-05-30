import time

from vulndix.stealth import StealthController, jitter_delay, pick_user_agent


def test_pick_user_agent_not_vulndix():
    ua = pick_user_agent()
    assert "VulnDix" not in ua
    assert "Mozilla" in ua


def test_jitter_delay_non_negative():
    assert jitter_delay(100) >= 0


def test_stealth_controller_backoff():
    ctl = StealthController(base_delay_ms=50, block_threshold=3)
    for _ in range(3):
        ctl.record_response(429)
    assert ctl.effective_threads <= 3
    ctl.wait_before_request()


def test_rate_limiter_spacing():
    ctl = StealthController(base_delay_ms=40, min_interval_s=0.05)
    t0 = time.perf_counter()
    ctl.wait_before_request()
    ctl.wait_before_request()
    assert time.perf_counter() - t0 >= 0.04
