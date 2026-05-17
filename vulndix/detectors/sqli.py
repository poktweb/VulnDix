from __future__ import annotations

import re
from typing import TYPE_CHECKING

from vulndix.detectors.helpers import make_finding as finding
from vulndix.models import BaselineResponse, Finding, InjectionPoint, ProbeResponse

if TYPE_CHECKING:
    import requests

    from vulndix.transport import build_session  # noqa: F401

SQL_SIGS = (
    "sql syntax",
    "mysql error",
    "sqlite error",
    "postgresql error",
    "ora-0",
    "ora-009",
    "unclosed quotation",
    "quoted string not properly terminated",
    "syntax error at or near",
    "warning: mysql",
    "mssql",
    "odbc sql server",
    "jdbc",
    "sqlstate",
    "you have an error in your sql",
)

SQLI_PAYLOAD_RE = re.compile(
    r"(?:'|\")|(?:\bor\b|\band\b)\s+[\d'\"]|--|#|/\*|union\s+select|1\s*=\s*1",
    re.IGNORECASE,
)

FALSE_REPLACEMENTS = (
    ("'1'='1", "'1'='2"),
    ('"1"="1', '"1"="2'),
    ("1=1", "1=2"),
    ("OR 1=1", "OR 1=2"),
    ("or 1=1", "or 1=2"),
)


def looks_like_sqli_payload(payload: str) -> bool:
    return bool(SQLI_PAYLOAD_RE.search(payload))


def derive_false_payload(payload: str) -> str | None:
    for src, dst in FALSE_REPLACEMENTS:
        if src in payload:
            return payload.replace(src, dst, 1)
    if re.search(r"1\s*=\s*1", payload, re.I):
        return re.sub(r"1\s*=\s*1", "1=2", payload, count=1, flags=re.I)
    return None


def _content_diff_suspicious(
    baseline: BaselineResponse,
    probe: ProbeResponse,
    payload: str,
) -> bool:
    if not looks_like_sqli_payload(payload):
        return False
    if probe.status >= 500 or baseline.status >= 500:
        return False
    if baseline.body_len < 80:
        return False
    diff = abs(len(probe.body) - baseline.body_len)
    min_diff = max(200, int(0.08 * baseline.body_len))
    if diff < min_diff:
        return False
    from vulndix.transport import body_hash

    if body_hash(probe.body) == baseline.body_hash:
        return False
    return True


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
    for sig in SQL_SIGS:
        if sig in body_l and sig not in base_l:
            return finding(
                "sqli",
                point,
                payload,
                "high",
                f"Erro SQL na resposta: {sig}",
            )

    if "sleep(5)" in payload.lower() and probe.elapsed_ms - baseline.elapsed_ms >= 4500:
        return finding(
            "sqli",
            point,
            payload,
            "medium",
            f"Possível time-based SQLi (delta {probe.elapsed_ms - baseline.elapsed_ms:.0f}ms)",
        )

    return None


def confirm_boolean_sqli(
    session: requests.Session,
    point: InjectionPoint,
    payload: str,
    baseline: BaselineResponse,
    true_probe: ProbeResponse,
) -> Finding | None:
    """
    Confirma SQLi booleano: payload TRUE vs FALSE devem diferir; pelo menos um difere do baseline.
    (Labs PortSwigger / filter?category= sem erro SQL na página.)
    """
    from vulndix.transport import send_probe

    false_payload = derive_false_payload(payload)
    if not false_payload or false_payload == payload:
        return None

    if not _content_diff_suspicious(baseline, true_probe, payload):
        return None

    false_probe = send_probe(session, point, false_payload)
    t_len = len(true_probe.body)
    f_len = len(false_probe.body)
    b_len = baseline.body_len

    if abs(t_len - f_len) < max(80, int(0.03 * max(t_len, f_len, 1))):
        return None

    true_off_baseline = abs(t_len - b_len) >= max(150, int(0.06 * b_len))
    false_off_baseline = abs(f_len - b_len) >= max(150, int(0.06 * b_len))
    if not true_off_baseline and not false_off_baseline:
        return None

    return finding(
        "sqli",
        point,
        payload,
        "high",
        (
            f"SQLi booleano: TRUE ({t_len}B) vs FALSE ({f_len}B) vs baseline ({b_len}B); "
            f"par confirmação FALSE={false_payload[:60]!r}"
        ),
    )
