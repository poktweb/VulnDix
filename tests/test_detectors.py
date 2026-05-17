from unittest.mock import MagicMock

from vulndix.detectors.sqli import confirm_boolean_sqli, detect as sqli_detect
from vulndix.detectors.xss import detect as xss_detect
from vulndix.filters import should_skip_param
from vulndix.models import BaselineResponse, InjectionPoint, ProbeResponse


def _baseline(snippet: str = "") -> BaselineResponse:
    return BaselineResponse(
        status=200,
        body_len=len(snippet),
        body_hash="abc",
        elapsed_ms=100,
        body_snippet=snippet,
    )


def _html_probe(body: str) -> ProbeResponse:
    return ProbeResponse(
        status=200,
        body=body,
        elapsed_ms=120,
        headers={"Content-Type": "text/html; charset=utf-8"},
    )


def test_skip_rsc_param():
    assert should_skip_param("_rsc") is True
    assert should_skip_param("id") is False


def test_xss_script_reflection():
    pt = InjectionPoint(
        url="https://example.com/?q=x",
        method="GET",
        location="query",
        name="q",
    )
    payload = "<script>alert(1)</script>"
    body = "<!DOCTYPE html><html><body>hello " + payload + " world</body></html>"
    f = xss_detect(pt, payload, _baseline("<html></html>"), _html_probe(body))
    assert f is not None
    assert f.type == "xss"


def test_xss_marker_only_rejected():
    pt = InjectionPoint(
        url="https://example.com/?_rsc=x",
        method="GET",
        location="query",
        name="q",
    )
    f = xss_detect(pt, "{{MARKER}}", _baseline(), _html_probe("VULNDIX_abc"))
    assert f is None


def test_xss_plain_marker_echo_rejected():
    pt = InjectionPoint(
        url="https://example.com/?q=1",
        method="GET",
        location="query",
        name="q",
    )
    body = '{"data":"VULNDIX_test123"}'
    probe = ProbeResponse(
        status=200,
        body=body,
        elapsed_ms=100,
        headers={"Content-Type": "application/json"},
    )
    f = xss_detect(pt, "VULNDIX_test123", _baseline("{}"), probe)
    assert f is None


def test_sqli_error():
    pt = InjectionPoint(
        url="https://example.com/?id=1",
        method="GET",
        location="query",
        name="id",
    )
    probe = ProbeResponse(
        status=500,
        body="You have an error in your SQL syntax",
        elapsed_ms=100,
    )
    f = sqli_detect(pt, "'", _baseline(), probe)
    assert f is not None
    assert f.type == "sqli"


def test_sqli_boolean_content_diff_not_in_error_detect():
    """Boolean SQLi não aparece em detect() — só após confirm_boolean_sqli."""
    pt = InjectionPoint(
        url="https://lab.net/filter?category=Gifts",
        method="GET",
        location="query",
        name="category",
        baseline_value="Gifts",
    )
    base_html = "<html>" + ("product " * 50) + "</html>"
    true_html = "<html>" + ("product " * 500) + "</html>"
    baseline = BaselineResponse(
        status=200,
        body_len=len(base_html),
        body_hash="aaa",
        elapsed_ms=100,
        body_snippet=base_html,
    )
    true_probe = ProbeResponse(status=200, body=true_html, elapsed_ms=110)
    assert sqli_detect(pt, "' OR '1'='1'--", baseline, true_probe) is None


def test_sqli_confirm_boolean_high(monkeypatch):
    pt = InjectionPoint(
        url="https://lab.net/filter?category=Gifts",
        method="GET",
        location="query",
        name="category",
        baseline_value="Gifts",
    )
    base_html = "<html>" + ("item " * 40) + "</html>"
    true_html = "<html>" + ("item " * 400) + "</html>"
    false_html = "<html>" + ("item " * 5) + "</html>"
    baseline = BaselineResponse(
        status=200,
        body_len=len(base_html),
        body_hash="aaa",
        elapsed_ms=100,
        body_snippet=base_html,
    )
    true_probe = ProbeResponse(status=200, body=true_html, elapsed_ms=110)

    def fake_send(_session, _point, payload):
        body = false_html if "'1'='2" in payload or "1=2" in payload else true_html
        return ProbeResponse(status=200, body=body, elapsed_ms=100)

    monkeypatch.setattr("vulndix.transport.send_probe", fake_send)
    f = confirm_boolean_sqli(MagicMock(), pt, "' OR '1'='1'--", baseline, true_probe)
    assert f is not None
    assert f.confidence == "high"
    assert "booleano" in f.evidence.lower()


