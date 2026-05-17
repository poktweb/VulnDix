from vulndix.models import ProbeResponse
from vulndix.transport import normalize_request_url, sanitize_headers, send_probe
from vulndix.models import InjectionPoint, ScanConfig
from vulndix.transport import build_session


def test_probe_response_body_len():
    p = ProbeResponse(status=200, body="abc", elapsed_ms=1.0)
    assert p.body_len == 3


def test_sanitize_headers_unicode():
    h = sanitize_headers({"X-Test": "café", "Referer": "https://x.com/\u2026"})
    for v in h.values():
        v.encode("latin-1")


def test_normalize_request_url_unicode_query():
    url = "https://example.com/search?q=café&x=1"
    safe = normalize_request_url(url)
    assert "caf" in safe or "%" in safe
    safe.encode("ascii")


def test_send_probe_unicode_baseline(monkeypatch):
    """Não deve lançar latin-1 ao enviar baseline com aspas curvas."""
    import requests

    calls: list[dict] = []

    class FakeResp:
        status_code = 200
        text = "ok"
        headers = {}

    def fake_get(self, url, **kwargs):
        calls.append(kwargs)
        hdrs = kwargs.get("headers", {})
        for k, v in hdrs.items():
            k.encode("latin-1")
            v.encode("latin-1")
        return FakeResp()

    monkeypatch.setattr(requests.Session, "get", fake_get)
    config = ScanConfig(url="https://example.com/")
    session = build_session(config)
    point = InjectionPoint(
        url="https://example.com/page?q=test",
        method="GET",
        location="query",
        name="q",
        baseline_value="\u201ccitação\u201d",
    )
    probe = send_probe(session, point, "\u201cteste\u201d")
    assert probe.status == 200
