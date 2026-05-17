from __future__ import annotations

from vulndix.detectors.helpers import make_finding as finding
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
    if "49" in probe.body and "49" not in baseline.body_snippet:
        if any(t in payload for t in ("{{7*7}}", "${7*7}", "7*7", "@(7*7)")):
            return finding(
                "ssti",
                point,
                payload,
                "medium",
                "Expressão de template avaliada (49 na resposta)",
            )
    return None
