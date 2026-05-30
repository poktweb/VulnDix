from vulndix.param_miner import extract_param_names_from_text, merge_mined_points
from vulndix.models import InjectionPoint


def test_extract_params_from_js():
    js = 'fetch("/api?q=test"); params.get("productId");'
    names = extract_param_names_from_text(js)
    assert "productId" in names or "q" in names


def test_merge_mined_points_dedupes():
    existing = [
        InjectionPoint(
            url="https://x.com/?id=1",
            method="GET",
            location="query",
            name="id",
            baseline_value="1",
        )
    ]
    mined = [
        InjectionPoint(
            url="https://x.com/?page=1",
            method="GET",
            location="query",
            name="page",
            baseline_value="1",
        )
    ]
    merged = merge_mined_points(existing, mined)
    assert len(merged) == 2
