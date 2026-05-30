from vulndix.fuzz_plan import (
    CANARY_PAYLOADS,
    payloads_for_tier,
    probe_has_anomaly,
)
from vulndix.models import BaselineResponse, ProbeResponse


def test_canary_payloads_exist_for_main_cats():
    assert "sqli" in CANARY_PAYLOADS
    assert "xss" in CANARY_PAYLOADS


def test_tier0_single_payload():
    full = ["a", "b", "c"]
    t0 = payloads_for_tier("sqli", full, 0)
    assert len(t0) == 1


def test_probe_has_anomaly_status_change():
    base = BaselineResponse(
        status=200,
        body_len=100,
        body_hash="abc",
        elapsed_ms=50.0,
        body_snippet="ok",
    )
    probe = ProbeResponse(status=500, body="err", elapsed_ms=55.0)
    assert probe_has_anomaly(base, probe)


def test_probe_no_anomaly_identical():
    from vulndix.transport import body_hash

    body = "same" * 20
    h = body_hash(body)
    base = BaselineResponse(
        status=200,
        body_len=len(body),
        body_hash=h,
        elapsed_ms=50.0,
        body_snippet=body,
    )
    probe = ProbeResponse(
        status=200,
        body=body,
        elapsed_ms=52.0,
        content_length=len(body),
    )
    assert not probe_has_anomaly(base, probe)
