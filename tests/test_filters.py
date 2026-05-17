from vulndix.filters import filter_points, should_skip_param
from vulndix.models import InjectionPoint


def test_filter_points_removes_rsc():
    points = [
        InjectionPoint(
            url="https://x.com/?_rsc=1",
            method="GET",
            location="query",
            name="_rsc",
        ),
        InjectionPoint(
            url="https://x.com/?id=1",
            method="GET",
            location="query",
            name="id",
        ),
    ]
    out = filter_points(points)
    assert len(out) == 1
    assert out[0].name == "id"
