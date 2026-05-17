from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from vulndix.models import Confidence, Finding, InjectionPoint, VulnType


def make_finding(
    vuln_type: VulnType,
    point: InjectionPoint,
    payload: str,
    confidence: Confidence,
    evidence: str,
) -> Finding:
    endpoint = point.url
    if point.location == "query":
        p = urlparse(point.url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[point.name] = [payload]
        new_q = urlencode(qs, doseq=True)
        endpoint = urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))
    return Finding(
        type=vuln_type,
        endpoint=endpoint,
        param=point.name,
        location=point.location,
        payload=payload,
        confidence=confidence,
        evidence=evidence,
    )
