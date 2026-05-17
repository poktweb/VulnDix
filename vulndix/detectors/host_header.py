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
    if point.location != "header" or point.name.lower() != "host":
        return None
    if payload.lower() not in ("127.0.0.1", "localhost", "evil.example.test"):
        return None
    from vulndix.transport import body_hash

    if body_hash(probe.body) != baseline.body_hash:
        if abs(len(probe.body) - baseline.body_len) > max(150, int(0.08 * baseline.body_len)):
            return finding(
                "host_header",
                point,
                payload,
                "medium",
                f"Resposta diferente com Host: {payload} (possível Host header attack)",
            )
    if "admin" in probe.body.lower() and "admin" not in baseline.body_snippet.lower():
        return finding(
            "host_header",
            point,
            payload,
            "high",
            f"Conteúdo admin com Host: {payload}",
        )
    return None
