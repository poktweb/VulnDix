from __future__ import annotations

import re

from vulndix.detectors.helpers import make_finding as finding
from vulndix.models import BaselineResponse, Finding, InjectionPoint, ProbeResponse

LDAP_ERROR_PATTERNS = (
    re.compile(r"ldap[_\s-]?err", re.I),
    re.compile(r"javax\.naming", re.I),
    re.compile(r"Invalid\s+DN\s+syntax", re.I),
    re.compile(r"Bad\s+search\s+filter", re.I),
    re.compile(r"Protocol\s+error", re.I),
    re.compile(r"ldap_search", re.I),
    re.compile(r"Operations\s+error", re.I),
    re.compile(r"data\s+0a", re.I),
    re.compile(r"ldap://", re.I),
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
    for pat in LDAP_ERROR_PATTERNS:
        if pat.search(probe.body) and not pat.search(baseline.body_snippet):
            return finding(
                "ldap",
                point,
                payload,
                "high",
                f"Erro LDAP/serviço de diretório exposto: {pat.pattern[:60]}",
            )
    if probe.status >= 500 and ("ldap" in probe.body.lower() or "naming" in probe.body.lower()):
        if probe.status != baseline.status or abs(probe.body_len - baseline.body_len) > 80:
            return finding(
                "ldap",
                point,
                payload,
                "medium",
                f"Resposta 5xx com indício LDAP (status {probe.status})",
            )
    return None
