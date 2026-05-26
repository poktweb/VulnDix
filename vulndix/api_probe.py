"""Sondagem leve de endpoints sensíveis (Swagger, GraphQL, backups, etc.)."""
from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

from vulndix.detectors.helpers import make_finding
from vulndix.models import Confidence, Finding, ScanConfig
from vulndix.reporter import eprint
from vulndix.transport import build_session

SENSITIVE_PATHS: tuple[tuple[str, str, str], ...] = (
    ("/swagger.json", "Swagger/OpenAPI JSON", "high"),
    ("/swagger-ui.html", "Swagger UI", "medium"),
    ("/v2/api-docs", "Spring API docs", "high"),
    ("/api/swagger.json", "API Swagger", "high"),
    ("/graphql", "GraphQL endpoint", "high"),
    ("/graphiql", "GraphiQL UI", "medium"),
    ("/.env", "Arquivo .env", "high"),
    ("/actuator/health", "Spring Actuator", "medium"),
    ("/server-status", "Apache server-status", "medium"),
    ("/debug", "Debug endpoint", "medium"),
    ("/phpinfo.php", "PHPInfo", "high"),
    ("/.git/HEAD", "Repositório Git exposto", "high"),
    ("/backup.sql", "Backup SQL", "high"),
    ("/web.config", "web.config", "medium"),
)

GRAPHQL_INTROSPECTION = (
    '{"query":"{ __schema { queryType { name } } }"}'
)

SWAGGER_MARKERS = ("swagger", '"openapi"', '"swagger"')
GRAPHQL_MARKERS = ('"__schema"', "__typename", "graphiql")
ENV_MARKERS = ("DB_PASSWORD", "APP_KEY", "SECRET_KEY", "AWS_SECRET")


def _probe_url(session: Any, url: str, config: ScanConfig) -> tuple[int, str, dict[str, str]]:
    try:
        r = session.get(
            url,
            timeout=config.probe_timeout_s,
            verify=config.verify_tls,
            allow_redirects=False,
        )
        body = r.text[: min(65536, config.probe_max_body_bytes)]
        return r.status_code, body, {k: v for k, v in r.headers.items()}
    except Exception:
        return 0, "", {}


def scan_exposed_apis(config: ScanConfig, browser_cookies: list[dict] | None = None) -> list[Finding]:
    if "api_exposed" not in config.categories:
        return []
    parsed = urlparse(config.url)
    if not parsed.scheme or not parsed.netloc:
        return []

    base = f"{parsed.scheme}://{parsed.netloc}"
    session = build_session(config, browser_cookies, pool_size=4)
    findings: list[Finding] = []
    seen: set[str] = set()

    for path, label, confidence in SENSITIVE_PATHS:
        url = urljoin(base + "/", path.lstrip("/"))
        status, body, _hdrs = _probe_url(session, url, config)
        if status not in (200, 201, 204, 301, 302, 401, 403):
            continue

        body_l = body.lower()
        hit = False
        evidence = f"HTTP {status} em {path}"

        if path == "/graphql" and status in (200, 400, 405):
            g_status, g_body, _ = _probe_url(session, url, config)
            if g_status in (200, 400):
                try:
                    r = session.post(
                        url,
                        data=GRAPHQL_INTROSPECTION,
                        headers={"Content-Type": "application/json"},
                        timeout=config.probe_timeout_s,
                        verify=config.verify_tls,
                    )
                    g_body = (r.text or "")[:8192]
                    g_status = r.status_code
                except Exception:
                    g_body = ""
                if any(m in g_body for m in GRAPHQL_MARKERS):
                    hit = True
                    evidence = "GraphQL com introspecção possível"
        elif path == "/.env":
            hit = any(m in body for m in ENV_MARKERS)
        elif "swagger" in path or "api-docs" in path:
            hit = any(m in body_l for m in SWAGGER_MARKERS)
        elif path == "/.git/HEAD":
            hit = body.strip().startswith("ref:")
        elif path == "/phpinfo.php":
            hit = "php version" in body_l or "phpinfo()" in body_l
        elif status == 200 and len(body) > 20:
            if path in ("/debug", "/server-status", "/actuator/health"):
                hit = status == 200 and (
                    "health" in body_l
                    or "apache" in body_l
                    or "status" in body_l
                    or '"status"' in body_l
                )
            elif path.endswith(".sql") or path == "/backup.sql":
                hit = "insert into" in body_l or "create table" in body_l
            else:
                hit = len(body) > 50

        if not hit:
            continue
        key = f"{path}:{label}"
        if key in seen:
            continue
        seen.add(key)
        from vulndix.models import InjectionPoint

        pt = InjectionPoint(url=url, method="GET", location="path", name=path)
        findings.append(
            make_finding(
                "api_exposed",
                pt,
                "(probe)",
                confidence,  # type: ignore[arg-type]
                f"Superfície exposta: {label} — {evidence}",
            )
        )
        eprint(f"[+] API_EXPOSED — {label} ({url})")

    return findings
