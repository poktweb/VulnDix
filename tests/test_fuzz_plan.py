from vulndix.fuzz_plan import (
    categories_for_point,
    dedupe_injection_points,
    filter_points_for_fast_fuzz,
)
from vulndix.models import InjectionPoint


def test_postid_gets_sqli_not_ssrf():
    pt = InjectionPoint(
        url="https://x.net/post?postId=1",
        method="GET",
        location="query",
        name="postId",
        baseline_value="1",
    )
    cats = categories_for_point(pt, frozenset({"sqli", "ssrf", "xss", "lfi", "host_header"}))
    assert "sqli" in cats
    assert "ssrf" not in cats
    assert "host_header" not in cats


def test_host_header_point():
    pt = InjectionPoint(
        url="https://x.net/",
        method="GET",
        location="header",
        name="Host",
    )
    cats = categories_for_point(pt, frozenset({"host_header", "sqli", "lfi", "xxe"}))
    assert frozenset(cats) == frozenset({"host_header", "sqli"})


def test_generic_param_skips_cmdi():
    pt = InjectionPoint(
        url="https://x.net/search?q=test",
        method="GET",
        location="query",
        name="q",
        baseline_value="test",
    )
    cats = categories_for_point(
        pt, frozenset({"xss", "sqli", "cmdi", "ssti", "lfi"}), category_cap=6
    )
    assert "cmdi" not in cats
    assert "xss" in cats


def test_dedupe_points():
    a = InjectionPoint("https://x/a", "GET", "query", "id", baseline_value="1")
    b = InjectionPoint("https://x/a", "GET", "query", "id", baseline_value="1")
    assert len(dedupe_injection_points([a, b])) == 1


def test_fast_header_filter():
    pts = [
        InjectionPoint("https://x/", "GET", "header", "Host"),
        InjectionPoint("https://x/", "GET", "header", "Referer"),
        InjectionPoint("https://x/", "GET", "header", "X-Forwarded-For"),
    ]
    out = filter_points_for_fast_fuzz(pts)
    assert len(out) == 1
    assert out[0].name == "Host"
