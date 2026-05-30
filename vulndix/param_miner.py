"""Mining de parâmetros (estilo dalfox): URLs/JS + probe canário antes de fuzz XSS."""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from vulndix.discover import host_in_scope, points_from_url
from vulndix.filters import should_skip_param
from vulndix.models import InjectionPoint, PageSample, ScanConfig
from vulndix.transport import send_probe

# Padrões comuns em JS (fetch, axios, location, query strings embutidas)
JS_PARAM_PATTERNS = (
    re.compile(r"""['"]([a-zA-Z_][\w]{1,48})['"]\s*:\s*['"`]"""),
    re.compile(r"""[?&]([a-zA-Z_][\w]{1,48})="""),
    re.compile(r"""\.get\(\s*['"]([a-zA-Z_][\w]{1,48})['"]\s*\)"""),
    re.compile(r"""searchParams\.(?:get|set|append)\(\s*['"]([a-zA-Z_][\w]{1,48})['"]"""),
    re.compile(r"""params\.(?:get|set)\(\s*['"]([a-zA-Z_][\w]{1,48})['"]"""),
)

URL_IN_TEXT = re.compile(
    r"""https?://[^\s"'<>]+""",
    re.IGNORECASE,
)

CANARY_MARKER_PREFIX = "VDX_CANARY_"


def extract_param_names_from_text(text: str) -> set[str]:
    found: set[str] = set()
    for pat in JS_PARAM_PATTERNS:
        for m in pat.finditer(text):
            name = m.group(1)
            if not should_skip_param(name) and len(name) <= 48:
                found.add(name)
    for url in URL_IN_TEXT.findall(text):
        p = urlparse(url)
        if p.query:
            for name in parse_qs(p.query, keep_blank_values=True):
                if not should_skip_param(name):
                    found.add(name)
    return found


def mine_params_from_samples(
    samples: list[PageSample],
    scope_host: str,
) -> set[str]:
    names: set[str] = set()
    for sample in samples:
        if not host_in_scope(sample.url, scope_host):
            continue
        names |= extract_param_names_from_text(sample.body)
        names |= extract_param_names_from_text(sample.url)
    return names


def injection_points_from_mined_params(
    base_url: str,
    param_names: set[str],
    headers: dict[str, str],
) -> list[InjectionPoint]:
    if not param_names:
        return []
    p = urlparse(base_url)
    root = f"{p.scheme}://{p.netloc}/"
    points: list[InjectionPoint] = []
    for name in sorted(param_names):
        if should_skip_param(name):
            continue
        url = f"{root}?{name}=1"
        points.extend(points_from_url(url, headers, fuzz_headers=False))
    return points


def merge_mined_points(
    existing: list[InjectionPoint],
    mined: list[InjectionPoint],
) -> list[InjectionPoint]:
    seen = {pt.key() for pt in existing}
    out = list(existing)
    for pt in mined:
        if pt.key() not in seen:
            seen.add(pt.key())
            out.append(pt)
    return out


def canary_reflects_in_response(marker: str, body: str) -> bool:
    return marker in body


def run_canary_probes(
    session: object,
    points: list[InjectionPoint],
    config: ScanConfig,
    marker: str,
) -> set[tuple[str, str, str, str]]:
    """Pontos onde o canário reflete — priorizar XSS depois."""
    hot: set[tuple[str, str, str, str]] = set()
    timeout = config.probe_timeout_s
    max_body = config.probe_max_body_bytes
    for pt in points:
        if pt.location not in ("query", "body", "json"):
            continue
        probe = send_probe(session, pt, marker, timeout=timeout, max_body_bytes=max_body)
        if canary_reflects_in_response(marker, probe.body):
            hot.add(pt.key())
    return hot
