from __future__ import annotations

from vulndix.detectors.helpers import make_finding as finding
from vulndix.models import BaselineResponse, Finding, InjectionPoint, ProbeResponse

XXE_SIGS = (
    "root:x:0:0",
    "boot loader",
    "for 16-bit",
    "entity",
    "DOCTYPE",
    "xml parsing",
    "simplexml",
    "lxml",
    "SAXParseException",
)


def detect(
    point: InjectionPoint,
    payload: str,
    baseline: BaselineResponse,
    probe: ProbeResponse,
    *,
    xss_marker: str = "",
    scope_host: str = "",
) -> Finding | None:
    if "<!entity" not in payload.lower() and "<!DOCTYPE" not in payload.upper():
        return None
    body_l = probe.body.lower()
    base_l = baseline.body_snippet.lower()
    for sig in XXE_SIGS:
        if sig.lower() in body_l and sig.lower() not in base_l:
            return finding("xxe", point, payload, "high", f"Indício XXE: {sig}")
    return None
