from __future__ import annotations

from vulndix.detectors.helpers import make_finding as finding
from vulndix.models import BaselineResponse, Finding, InjectionPoint, ProbeResponse

NOSQL_SIGS = (
    "mongodb",
    "cannot exec",
    "bad query",
    "unknown operator",
    "unterminated string",
    "json parse",
    "bson",
    "syntax error",
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
    for sig in NOSQL_SIGS:
        if sig in body_l and sig not in base_l:
            return finding("nosql", point, payload, "high", f"Assinatura NoSQL: {sig}")

    if any(x in payload for x in ("$gt", "$ne", "$where", "||")):
        if probe.status == 200 and baseline.status in (401, 403) and probe.status != baseline.status:
            return finding(
                "nosql",
                point,
                payload,
                "high",
                f"Bypass de autenticação (status {baseline.status} → {probe.status})",
            )
        from vulndix.transport import body_hash

        if abs(len(probe.body) - baseline.body_len) > max(200, int(0.1 * baseline.body_len)):
            if body_hash(probe.body) != baseline.body_hash:
                if "login" in body_l or "account" in body_l or "welcome" in body_l:
                    return finding(
                        "nosql",
                        point,
                        payload,
                        "medium",
                        "Resposta pós-login diferente do baseline (possível NoSQLi)",
                    )
    return None
