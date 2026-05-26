from __future__ import annotations

from vulndix.models import (
    BaselineResponse,
    Finding,
    InjectionPoint,
    ProbeResponse,
    VulnType,
)

_DETECTORS: dict[VulnType, str] = {
    "xss": "vulndix.detectors.xss",
    "sqli": "vulndix.detectors.sqli",
    "lfi": "vulndix.detectors.lfi",
    "ssti": "vulndix.detectors.ssti",
    "cmdi": "vulndix.detectors.cmdi",
    "redirect": "vulndix.detectors.redirect",
    "traversal": "vulndix.detectors.traversal",
    "nosql": "vulndix.detectors.nosql",
    "ssrf": "vulndix.detectors.ssrf",
    "xxe": "vulndix.detectors.xxe",
    "host_header": "vulndix.detectors.host_header",
    "crlf": "vulndix.detectors.crlf",
    "ldap": "vulndix.detectors.ldap",
}


def detect_all(
    vuln_type: VulnType,
    point: InjectionPoint,
    payload: str,
    baseline: BaselineResponse,
    probe: ProbeResponse,
    *,
    xss_marker: str = "",
    scope_host: str = "",
) -> Finding | None:
    mod_path = _DETECTORS.get(vuln_type)
    if not mod_path:
        return None
    import importlib

    mod = importlib.import_module(mod_path)
    return mod.detect(
        point,
        payload,
        baseline,
        probe,
        xss_marker=xss_marker,
        scope_host=scope_host,
    )
