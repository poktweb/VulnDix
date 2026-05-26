from __future__ import annotations

import re

from vulndix.detectors.helpers import make_finding
from vulndix.models import Finding, PageSample, ScanConfig

INFO_PATTERNS = (
    (r"Traceback \(most recent call last\)", "Stack trace Python"),
    (r"at java\.", "Stack trace Java"),
    (r"SQL syntax.*MySQL", "Erro SQL exposto"),
    (r"Warning:.*mysqli", "Warning PHP/MySQL"),
    (r"pg_query\(\)", "Erro PostgreSQL"),
    (r"Unclosed quotation mark", "Erro SQL (aspas)"),
    (r"Syntax error.*ODBC", "Erro ODBC"),
    (r"\/var\/www\/", "Caminho de servidor exposto"),
    (r"\/home\/", "Caminho Linux exposto"),
    (r"C:\\\\inetpub", "Caminho Windows exposto"),
    (r"AKIA[0-9A-Z]{16}", "Possível chave AWS exposta"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Chave privada no corpo"),
    (r"api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9]{16,}", "API key em texto"),
)

JWT_WEAK_RE = re.compile(r'["\']alg["\']\s*:\s*["\']none["\']', re.I)

CSRF_FORM_RE = re.compile(r"<form[^>]*method\s*=\s*['\"]?post", re.I)


def run_passive_checks(pages: list[PageSample], config: ScanConfig) -> list[Finding]:
    if not pages:
        return []
    findings: list[Finding] = []
    seen: set[str] = set()

    for page in pages:
        hdrs = {k.lower(): v for k, v in page.headers.items()}
        body_l = page.body.lower()

        # Clickjacking — labs de clickjacking / proteção de frame
        if "clickjacking" in config.categories:
            xfo = hdrs.get("x-frame-options", "")
            csp = hdrs.get("content-security-policy", "")
            if not xfo and "frame-ancestors" not in csp.lower():
                key = f"clickjacking:{page.url}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        make_finding(
                            "clickjacking",
                            _fake_point(page.url, "headers"),
                            "(passivo)",
                            "medium",
                            "Sem X-Frame-Options nem CSP frame-ancestors",
                        )
                    )

        # CORS — labs CORS
        if "cors" in config.categories:
            acao = hdrs.get("access-control-allow-origin", "")
            acac = hdrs.get("access-control-allow-credentials", "").lower()
            if acao == "*" and acac == "true":
                key = f"cors:{page.url}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        make_finding(
                            "cors",
                            _fake_point(page.url, "cors"),
                            "(passivo)",
                            "high",
                            "Access-Control-Allow-Origin: * com Allow-Credentials: true",
                        )
                    )
            elif acao and acao not in ("null", "") and "evil" not in acao:
                if acac == "true" and page.url.split("/")[2] not in acao:
                    key = f"cors-reflect:{page.url}:{acao}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            make_finding(
                                "cors",
                                _fake_point(page.url, "cors"),
                                acao,
                                "medium",
                                f"CORS reflete origem com credenciais: {acao[:80]}",
                            )
                        )

        # Security headers ausentes
        if "sec_headers" in config.categories:
            missing: list[str] = []
            if not hdrs.get("strict-transport-security"):
                missing.append("HSTS")
            csp = hdrs.get("content-security-policy", "")
            if not csp:
                missing.append("CSP")
            if not hdrs.get("x-content-type-options"):
                missing.append("X-Content-Type-Options")
            if not hdrs.get("referrer-policy"):
                missing.append("Referrer-Policy")
            if not hdrs.get("permissions-policy") and not hdrs.get("feature-policy"):
                missing.append("Permissions-Policy")
            if missing:
                key = f"sec_headers:{page.url}:{','.join(missing)}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        make_finding(
                            "sec_headers",
                            _fake_point(page.url, "headers"),
                            "(passivo)",
                            "low",
                            f"Cabeçalhos de segurança ausentes: {', '.join(missing)}",
                        )
                    )

        # Cookies inseguros (Set-Cookie na resposta)
        if "cookie_sec" in config.categories:
            for raw_name, raw_val in page.headers.items():
                if raw_name.lower() != "set-cookie":
                    continue
                for cookie_chunk in raw_val.split(","):
                    c_low = cookie_chunk.strip().lower()
                    issues: list[str] = []
                    if "secure" not in c_low and page.url.startswith("https"):
                        issues.append("sem Secure")
                    if "httponly" not in c_low:
                        issues.append("sem HttpOnly")
                    if "samesite" not in c_low:
                        issues.append("sem SameSite")
                    if issues:
                        key = f"cookie_sec:{page.url}:{cookie_chunk[:40]}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(
                                make_finding(
                                    "cookie_sec",
                                    _fake_point(page.url, "set-cookie"),
                                    "(passivo)",
                                    "medium",
                                    f"Cookie inseguro ({', '.join(issues)})",
                                )
                            )

        # JWT fraco / alg none em resposta
        if "info" in config.categories and JWT_WEAK_RE.search(page.body):
            key = f"jwt_weak:{page.url}"
            if key not in seen:
                seen.add(key)
                findings.append(
                    make_finding(
                        "info",
                        _fake_point(page.url, "jwt"),
                        "(passivo)",
                        "high",
                        "JWT com algoritmo 'none' ou configuração fraca detectada",
                    )
                )

        # Information disclosure
        if "info" in config.categories:
            for pat, label in INFO_PATTERNS:
                if re.search(pat, page.body, re.I):
                    key = f"info:{label}:{page.url}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            make_finding(
                                "info",
                                _fake_point(page.url, "response"),
                                "(passivo)",
                                "medium",
                                f"Vazamento de informação: {label}",
                            )
                        )
                    break

        # CSRF — formulários POST sem token visível
        if "csrf" in config.categories:
            if CSRF_FORM_RE.search(page.body):
                has_token = bool(
                    re.search(
                        r"(csrf|token|authenticity|__requestverification)",
                        page.body,
                        re.I,
                    )
                )
                if not has_token and "/login" not in page.url.lower():
                    key = f"csrf:{page.url}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            make_finding(
                                "csrf",
                                _fake_point(page.url, "form"),
                                "(passivo)",
                                "low",
                                "Formulário POST sem campo anti-CSRF aparente",
                            )
                        )

    return findings


def _fake_point(url: str, name: str):
    from vulndix.models import InjectionPoint

    return InjectionPoint(url=url, method="GET", location="query", name=name)
