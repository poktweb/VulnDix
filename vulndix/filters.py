from __future__ import annotations

import re
from urllib.parse import urlparse

from vulndix.models import InjectionPoint, ProbeResponse

# Parâmetros de framework/CDN/analytics — reflexão esperada, não são superfície de ataque
SKIP_PARAMS = frozenset(
    {
        "_rsc",
        "_next",
        "__next",
        "__nextjs",
        "__nextdata",
        "_nextdata",
        "cb",
        "_cb",
        "_buildid",
        "ver",
        "v",
        "cache",
        "nocache",
        "timestamp",
        "ts",
        "_t",
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_content",
        "utm_term",
        "gclid",
        "fbclid",
        "mc_cid",
        "mc_eid",
    }
)

SKIP_EXTENSIONS = frozenset(
    {
        ".pdf",
        ".zip",
        ".rar",
        ".7z",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".svg",
        ".css",
        ".js",
        ".mjs",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".ico",
        ".mp4",
        ".webm",
        ".mp3",
        ".xml",
        ".json",
    }
)

DANGEROUS_PAYLOAD_MARKERS = (
    "<script",
    "</script>",
    "onerror",
    "onload",
    "onclick",
    "onfocus",
    "javascript:",
    "<svg",
    "<img",
    "<iframe",
    "alert(",
)

_HTML_CONTEXT_RE = re.compile(
    r"(<script[^>]*>[^<]*{needle}|<[^>]+\s+\w+\s*=\s*['\"]?[^'\">]*{needle}|{needle}[^<]*</script>)",
    re.IGNORECASE | re.DOTALL,
)


def should_skip_param(name: str) -> bool:
    low = name.lower()
    if low in SKIP_PARAMS:
        return True
    if low.startswith("__"):
        return True
    return False


def is_skippable_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    for ext in SKIP_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False


def filter_points(points: list[InjectionPoint]) -> list[InjectionPoint]:
    return [p for p in points if not should_skip_param(p.name)]


def response_is_html(probe: ProbeResponse) -> bool:
    ct = (probe.headers.get("Content-Type") or probe.headers.get("content-type") or "").lower()
    if any(x in ct for x in ("application/json", "text/x-component", "application/javascript", "text/plain")):
        if "text/html" not in ct:
            return False
    body_start = (probe.body or "")[:800].lower()
    if "<html" in body_start or "<!doctype html" in body_start:
        return True
    return "text/html" in ct


def payload_is_dangerous(payload: str) -> bool:
    low = payload.lower()
    return any(m in low for m in DANGEROUS_PAYLOAD_MARKERS)


def marker_only_payload(payload: str) -> bool:
    stripped = payload.strip()
    return stripped in ("{{MARKER}}", "{{marker}}") or stripped == ""


def xss_reflected_in_dangerous_context(body: str, needle: str) -> bool:
    if not needle or needle not in body:
        return False
    if payload_is_dangerous(needle):
        return True
    pattern = _HTML_CONTEXT_RE.pattern.replace("{needle}", re.escape(needle))
    if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
        return True
    idx = body.find(needle)
    window = body[max(0, idx - 120) : idx + len(needle) + 120]
    if re.search(r"<script\b", window, re.I) and needle in window:
        return True
    if re.search(rf"""=\s*['"]?[^'"]*{re.escape(needle)}""", window):
        return True
    return False


def bodies_substantially_different(baseline_snippet: str, probe_body: str, needle: str) -> bool:
    """Evita alertar quando só o token de teste aparece em canal não-HTML com corpo quase idêntico."""
    if not needle or needle not in probe_body:
        return False
    if needle in baseline_snippet:
        return False
    base_len = len(baseline_snippet)
    probe_len = len(probe_body)
    if base_len > 0 and abs(probe_len - base_len) < 50:
        stripped_base = baseline_snippet.replace(needle, "")
        stripped_probe = probe_body.replace(needle, "")
        if stripped_base == stripped_probe:
            return False
    return True
