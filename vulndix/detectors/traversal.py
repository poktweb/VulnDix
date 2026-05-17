from __future__ import annotations

from vulndix.detectors.helpers import make_finding as finding
from vulndix.models import BaselineResponse, Finding, InjectionPoint, ProbeResponse

TRAV_SIGS = (
    "root:x:0:0:",
    "[boot loader]",
    "permission denied",
    "no such file",
    "directory listing",
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
    body_l = probe.body.lower()
    base_l = baseline.body_snippet.lower()
    for sig in TRAV_SIGS:
        if sig in body_l and sig not in base_l:
            return finding(
                "traversal",
                point,
                payload,
                "medium",
                f"Assinatura path traversal: {sig}",
            )
    probe_len = len(probe.body)
    if abs(probe_len - baseline.body_len) > 500 and (".." in payload or "%2e" in payload.lower()):
        if probe.status != baseline.status:
            return finding(
                "traversal",
                point,
                payload,
                "low",
                f"Resposta diferente (status {probe.status} vs {baseline.status}, delta len {abs(probe_len - baseline.body_len)})",
            )
    return None
