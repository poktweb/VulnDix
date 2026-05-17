from __future__ import annotations

from vulndix.detectors.helpers import make_finding as finding
from vulndix.models import BaselineResponse, Finding, InjectionPoint, ProbeResponse

LFI_SIGS = (
    "root:x:0:0:",
    "[boot loader]",
    "[extensions]",
    "for 16-bit app support",
    "failed opening",
    "include_path",
    "open_basedir restriction",
    "no such file or directory in",
    "warning: include(",
    "warning: require(",
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
    for sig in LFI_SIGS:
        if sig.lower() in body_l and sig.lower() not in base_l:
            return finding(
                "lfi",
                point,
                payload,
                "high",
                f"Assinatura LFI: {sig}",
            )
    return None
