from __future__ import annotations

import re

from vulndix.detectors.helpers import make_finding as finding
from vulndix.models import BaselineResponse, Finding, InjectionPoint, ProbeResponse

CMD_PATTERNS = (
    re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+", re.I),
    re.compile(r"groups=\d+", re.I),
    re.compile(r"whoami[:\s]+[\w\\-]+", re.I),
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
    for pat in CMD_PATTERNS:
        m = pat.search(probe.body)
        if m and not pat.search(baseline.body_snippet):
            return finding(
                "cmdi",
                point,
                payload,
                "high",
                f"Saída de comando detectada: {m.group(0)[:80]}",
            )
    return None
