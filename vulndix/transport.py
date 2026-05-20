from __future__ import annotations

import hashlib
import shlex
import subprocess
import time
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

import requests
import urllib3
from requests.adapters import HTTPAdapter

from vulndix.models import BaselineResponse, InjectionPoint, ProbeResponse, ScanConfig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def body_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _latin1_safe(text: str) -> str:
    """HTTP/1.1 exige headers em latin-1; evita crash com Unicode do crawl."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {_latin1_safe(k): _latin1_safe(v) for k, v in headers.items()}


def normalize_request_url(url: str) -> str:
    """Garante URL válida para requests (query/path com acentos, aspas curvas, etc.)."""
    p = urlparse(url)
    path = quote(p.path or "/", safe="/%:@", encoding="utf-8")
    query = p.query
    if query:
        qs = parse_qs(query, keep_blank_values=True)
        query = urlencode(qs, doseq=True, encoding="utf-8", errors="replace")
    return urlunparse((p.scheme, p.netloc, path, p.params, query, p.fragment))


def build_session(
    config: ScanConfig,
    cookies_from_browser: list[dict[str, Any]] | None = None,
    *,
    pool_size: int = 0,
) -> requests.Session:
    sess = requests.Session()
    pool = pool_size or max(10, config.threads * 2)
    adapter = HTTPAdapter(pool_connections=pool, pool_maxsize=pool, max_retries=0)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    sess.headers.update({"User-Agent": config.user_agent})
    sess.headers.update(config.extra_headers)
    if config.token:
        tok = config.token if config.token.lower().startswith("bearer ") else f"Bearer {config.token}"
        sess.headers["Authorization"] = tok
    for raw in config.cookies:
        if "=" in raw:
            name, val = raw.split("=", 1)
            sess.cookies.set(name.strip(), val.strip())
    if cookies_from_browser:
        for c in cookies_from_browser:
            name = c.get("name")
            value = c.get("value")
            domain = c.get("domain", "")
            if name and value is not None:
                sess.cookies.set(name, value, domain=domain.lstrip("."))
    sess.verify = config.verify_tls
    return sess


def apply_payload(point: InjectionPoint, payload: str) -> tuple[str, dict[str, str], dict[str, Any] | str | None]:
    headers = dict(point.headers)
    body: dict[str, Any] | str | None = None
    url = point.url

    if point.location == "header":
        headers[point.name] = payload
        return url, headers, point.body

    if point.location == "query":
        p = urlparse(point.url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[point.name] = [payload]
        new_q = urlencode(qs, doseq=True, encoding="utf-8", errors="replace")
        url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))
        return normalize_request_url(url), headers, None

    if point.location == "body" and isinstance(point.body, dict):
        body = dict(point.body)
        body[point.name] = payload
        return point.url, headers, body

    if point.location == "json" and isinstance(point.body, dict):
        body = dict(point.body)
        body[point.name] = payload
        return point.url, headers, body

    if point.location == "path":
        if point.baseline_value and point.baseline_value in point.url:
            url = point.url.replace(point.baseline_value, payload, 1)
        else:
            url = point.url + payload
        return normalize_request_url(url), headers, point.body

    if point.location == "xml":
        headers["Content-Type"] = "application/xml"
        return point.url, headers, payload

    return url, headers, point.body


def _read_limited_response(r: requests.Response, max_bytes: int) -> tuple[str, int]:
    """Lê só o necessário do corpo (scanners profissionais limitam buffer)."""
    cl_hdr = r.headers.get("Content-Length", "")
    try:
        declared = int(cl_hdr) if cl_hdr.isdigit() else 0
    except (TypeError, ValueError):
        declared = 0

    if max_bytes <= 0 or not hasattr(r, "iter_content"):
        text = r.text or ""
        return text, declared or len(text)

    chunks: list[bytes] = []
    total = 0
    for chunk in r.iter_content(chunk_size=16384):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            break
    raw = b"".join(chunks)
    text = raw.decode(r.encoding or "utf-8", errors="replace")
    full_len = declared if declared > 0 else max(len(text), total)
    return text, full_len


def send_probe(
    session: requests.Session,
    point: InjectionPoint,
    payload: str,
    timeout: float = 12.0,
    *,
    max_body_bytes: int = 98304,
) -> ProbeResponse:
    url, headers, body = apply_payload(point, payload)
    url = normalize_request_url(url)
    method = point.method.upper()
    hdrs = sanitize_headers({**dict(session.headers), **headers})
    start = time.perf_counter()
    stream_kw = {"stream": True}
    try:
        if method == "GET":
            r = session.get(
                url, headers=hdrs, timeout=timeout, allow_redirects=False, **stream_kw
            )
        elif point.location == "json" and isinstance(body, dict):
            r = session.request(
                method,
                url,
                headers={**hdrs, "Content-Type": "application/json"},
                json=body,
                timeout=timeout,
                allow_redirects=False,
                **stream_kw,
            )
        elif isinstance(body, dict):
            safe_body = {k: _latin1_safe(str(v)) for k, v in body.items()}
            r = session.request(
                method,
                url,
                headers=hdrs,
                data=safe_body,
                timeout=timeout,
                allow_redirects=False,
                **stream_kw,
            )
        elif point.location == "xml" and isinstance(body, str):
            r = session.request(
                method,
                url,
                headers={**hdrs, "Content-Type": "application/xml"},
                data=body.encode("utf-8"),
                timeout=timeout,
                allow_redirects=False,
                **stream_kw,
            )
        else:
            r = session.request(
                method, url, headers=hdrs, timeout=timeout, allow_redirects=False, **stream_kw
            )
    except requests.RequestException as e:
        elapsed = (time.perf_counter() - start) * 1000
        return ProbeResponse(status=0, body=str(e), elapsed_ms=elapsed, headers={})
    elapsed = (time.perf_counter() - start) * 1000
    text, full_len = _read_limited_response(r, max_body_bytes)
    close = getattr(r, "close", None)
    if callable(close):
        close()
    return ProbeResponse(
        status=r.status_code,
        body=text,
        elapsed_ms=elapsed,
        headers=dict(r.headers),
        content_length=full_len,
    )


def baseline_from_probe(probe: ProbeResponse) -> BaselineResponse:
    snippet = probe.body[:8000]
    return BaselineResponse(
        status=probe.status,
        body_len=len(probe.body),
        body_hash=body_hash(probe.body),
        elapsed_ms=probe.elapsed_ms,
        body_snippet=snippet,
        headers=probe.headers,
    )


def build_curl_command(
    session: requests.Session,
    point: InjectionPoint,
    payload: str,
    insecure: bool,
) -> str:
    url, headers, body = apply_payload(point, payload)
    method = point.method.upper()
    parts = ["curl", "-sS", "-D", "-", "-o", "NUL" if _is_windows() else "/dev/null"]
    if insecure:
        parts.append("-k")
    parts.extend(["-X", method])
    for k, v in {**dict(session.headers), **headers}.items():
        if k.lower() in ("content-length",):
            continue
        parts.extend(["-H", f"{k}: {v}"])
    if point.location == "json" and isinstance(body, dict):
        import json

        parts.extend(["-H", "Content-Type: application/json"])
        parts.extend(["--data", json.dumps(body)])
    elif isinstance(body, dict):
        parts.extend(["--data", urlencode(body)])
    parts.append(url)
    return " ".join(shlex.quote(p) if " " in p or p in ('-D', '-o') else p for p in parts)


def _is_windows() -> bool:
    import sys

    return sys.platform.startswith("win")


def verify_with_curl(curl_cmd: str, timeout: int = 25) -> bool:
    try:
        subprocess.run(
            curl_cmd,
            shell=True,
            capture_output=True,
            timeout=timeout,
        )
        return True
    except (subprocess.TimeoutExpired, OSError):
        return False
