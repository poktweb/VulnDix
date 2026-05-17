from __future__ import annotations

import re
from typing import Any

from vulndix.detectors.helpers import make_finding
from vulndix.models import Finding, InjectionPoint, ScanConfig
from vulndix.reporter import eprint
from vulndix.transport import baseline_from_probe, send_probe

IDOR_PARAM_RE = re.compile(
    r"^(id|productid|product_id|user|userid|user_id|account|order|orderid|doc|file)$",
    re.I,
)

SENSITIVE_MARKERS = (
    "administrator",
    "delete user",
    "wiener",
    "carlos",
    "role",
    "privilege",
    "unauthorized",
)


def scan_idor(
    session: Any,
    points: list[InjectionPoint],
    config: ScanConfig,
) -> list[Finding]:
    if "idor" not in config.categories:
        return []
    findings: list[Finding] = []
    seen: set[str] = set()

    for point in points:
        if not IDOR_PARAM_RE.match(point.name):
            continue
        val = (point.baseline_value or "").strip()
        if not val.isdigit():
            continue
        num = int(val)
        for alt in (str(num + 1), str(num - 1), "1", "2"):
            if alt == val or int(alt) < 0:
                continue
            alt_point = InjectionPoint(
                url=point.url,
                method=point.method,
                location=point.location,
                name=point.name,
                baseline_value=point.baseline_value,
                headers=dict(point.headers),
                body=point.body,
                url_template=point.url_template,
            )
            probe = send_probe(session, alt_point, alt)
            base_probe = send_probe(session, point, val)
            base = baseline_from_probe(base_probe)
            body_l = probe.body.lower()
            if probe.status == 200 and base.status in (200, 403):
                hit = any(m in body_l for m in SENSITIVE_MARKERS)
                if hit or (len(probe.body) > base.body_len + 300):
                    key = f"{point.url_template}:{point.name}:{alt}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        make_finding(
                            "idor",
                            alt_point,
                            alt,
                            "medium",
                            f"ID {alt} acessível (baseline {val}); possível IDOR / access control",
                        )
                    )
                    eprint(f"[+] IDOR {point.name}={alt} — recurso alternativo acessível")
                    break
    return findings
