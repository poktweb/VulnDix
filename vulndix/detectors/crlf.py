from __future__ import annotations

import re

from vulndix.detectors.helpers import make_finding as finding
from vulndix.models import BaselineResponse, Finding, InjectionPoint, ProbeResponse

CRLF_MARKERS = (
    re.compile(r"set-cookie\s*:\s*injected", re.I),
    re.compile(r"x-injected\s*:\s*1", re.I),
    re.compile(r"location\s*:\s*https?://evil\.example", re.I),
)

BODY_SPLIT_RE = re.compile(r"(?:\r\n|\n)Set-Cookie:\s*injected", re.I)


def detect(
    point: InjectionPoint,
    payload: str,
    baseline: BaselineResponse,
    probe: ProbeResponse,
    *,
    xss_marker: str = "",
    scope_host: str = "",
) -> Finding | None:
    hdr_blob = "\n".join(f"{k}: {v}" for k, v in probe.headers.items())
    for pat in CRLF_MARKERS:
        if pat.search(hdr_blob) and not pat.search(
            "\n".join(f"{k}: {v}" for k, v in baseline.headers.items())
        ):
            return finding(
                "crlf",
                point,
                payload,
                "high",
                "Cabeçalho HTTP injetado via CRLF na resposta",
            )

    if BODY_SPLIT_RE.search(probe.body) and not BODY_SPLIT_RE.search(baseline.body_snippet):
        return finding(
            "crlf",
            point,
            payload,
            "medium",
            "Quebra de linha CRLF refletida no corpo (possível injeção de header)",
        )

    if "%0d%0a" in payload.lower() or "\\r\\n" in payload:
        if "injected=1" in probe.body.lower() and "injected=1" not in baseline.body_snippet.lower():
            return finding(
                "crlf",
                point,
                payload,
                "medium",
                "Valor de cookie/header injetado refletido na resposta",
            )
    return None
