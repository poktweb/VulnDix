from __future__ import annotations

from vulndix.detectors.helpers import make_finding as finding
from vulndix.filters import (
    bodies_substantially_different,
    marker_only_payload,
    payload_is_dangerous,
    response_is_html,
    xss_reflected_in_dangerous_context,
)
from vulndix.models import BaselineResponse, Finding, InjectionPoint, ProbeResponse


def detect(
    point: InjectionPoint,
    payload: str,
    baseline: BaselineResponse,
    probe: ProbeResponse,
    *,
    xss_marker: str = "",
    scope_host: str = "",
) -> Finding | None:
    if marker_only_payload(payload):
        return None

    if not response_is_html(probe):
        return None

    check = payload
    if xss_marker and "{{MARKER}}" in payload:
        check = payload.replace("{{MARKER}}", xss_marker)

    if check not in probe.body:
        return None

    if check in baseline.body_snippet and not payload_is_dangerous(check):
        return None

    if not bodies_substantially_different(baseline.body_snippet, probe.body, check):
        return None

    if not xss_reflected_in_dangerous_context(probe.body, check):
        return None

    confidence = "high" if payload_is_dangerous(check) else "medium"
    ctx = "payload perigoso refletido em HTML"
    if "<script" in check.lower():
        ctx = "tag <script> refletida sem escape aparente"
    elif "onerror" in check.lower() or "onload" in check.lower():
        ctx = "handler de evento refletido em HTML"

    return finding("xss", point, payload, confidence, ctx)
