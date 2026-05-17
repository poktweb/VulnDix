from __future__ import annotations

from urllib.parse import urlparse

from vulndix.detectors.helpers import make_finding as finding
from vulndix.models import BaselineResponse, Finding, InjectionPoint, ProbeResponse

EVIL_HOST = "evil.example.test"


def detect(
    point: InjectionPoint,
    payload: str,
    baseline: BaselineResponse,
    probe: ProbeResponse,
    *,
    xss_marker: str = "",
    scope_host: str = "",
) -> Finding | None:
    loc = probe.headers.get("Location") or probe.headers.get("location") or ""
    if not loc:
        return None
    try:
        host = (urlparse(loc).hostname or "").lower()
    except Exception:
        return None
    if EVIL_HOST in host or (host and scope_host and host != scope_host.lower() and "evil.example" in loc):
        return finding(
            "redirect",
            point,
            payload,
            "medium",
            f"Location externo: {loc[:200]}",
        )
    if loc.startswith(("http://", "https://")) and scope_host:
        if host and host != scope_host.lower() and not host.endswith("." + scope_host.lower()):
            if "evil.example" in loc or EVIL_HOST in loc:
                return finding(
                    "redirect",
                    point,
                    payload,
                    "medium",
                    f"Open redirect para: {loc[:200]}",
                )
    return None
