from __future__ import annotations

from vulndix.detectors.helpers import make_finding as finding
from vulndix.models import BaselineResponse, Finding, InjectionPoint, ProbeResponse

SSRF_SIGS = (
    "ami-id",
    "instance-id",
    "root:x:0:0",
    "localhost",
    "connection refused",
    "could not connect",
    "failed to connect",
    "internal server",
    "metadata.google",
    "169.254.169.254",
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
    if not any(x in payload for x in ("127.0.0.1", "localhost", "169.254", "[::1]", "file://")):
        return None
    body_l = probe.body.lower()
    base_l = baseline.body_snippet.lower()
    for sig in SSRF_SIGS:
        if sig in body_l and sig not in base_l:
            return finding("ssrf", point, payload, "high", f"Indício SSRF: {sig}")
    if probe.status != baseline.status and probe.status in (200, 500, 502):
        if abs(len(probe.body) - baseline.body_len) > 100:
            return finding(
                "ssrf",
                point,
                payload,
                "medium",
                f"Resposta alterada ao apontar para URL interna (status {probe.status})",
            )
    return None
