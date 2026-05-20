from vulndix.discover import (
    dedupe_points,
    normalize_url_template,
    points_from_url,
    synthetic_probe_points,
)


def test_normalize_url_template():
    t = normalize_url_template("https://example.com/page?id=1&page=2")
    assert "id={}" in t
    assert "page={}" in t


def test_points_from_url_query():
    pts = points_from_url("https://example.com/x?id=5&q=test", {}, False)
    names = {p.name for p in pts}
    assert "id" in names
    assert "q" in names


def test_synthetic_probe_points():
    pts = synthetic_probe_points(
        ["https://example.com/", "https://example.com/about"],
        {},
        "example.com",
        max_endpoints=2,
    )
    names = {p.name for p in pts}
    assert "id" in names
    assert "productId" in names
    assert any(p.location == "query" for p in pts)


def test_dedupe_points():
    from vulndix.models import InjectionPoint

    a = InjectionPoint(
        url="https://example.com/?id=1",
        method="GET",
        location="query",
        name="id",
        baseline_value="1",
    )
    b = InjectionPoint(
        url="https://example.com/?id=2",
        method="GET",
        location="query",
        name="id",
        baseline_value="2",
    )
    out = dedupe_points([a, b])
    assert len(out) == 1
