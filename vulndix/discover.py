from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from vulndix.filters import is_skippable_url, should_skip_param
from vulndix.models import InjectionPoint, Location

SKIP_INPUT_TYPES = frozenset({"submit", "button", "image", "reset", "file"})
MAX_SYNTHETIC_ENDPOINTS = 25
MAX_SYNTHETIC_PARAMS_PER_URL = 14

# Parâmetros comuns quando o site não expõe ?id= no HTML (SPAs, marketing sites)
COMMON_PROBE_PARAMS: tuple[tuple[str, str], ...] = (
    ("id", "1"),
    ("page", "1"),
    ("productId", "1"),
    ("product_id", "1"),
    ("cat", "1"),
    ("category", "test"),
    ("q", "test"),
    ("search", "test"),
    ("query", "test"),
    ("redirect", "/"),
    ("url", "https://example.com"),
    ("file", "index.html"),
    ("lang", "en"),
    ("ref", "1"),
)

FUZZ_HEADER_NAMES = (
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "Host",
)


def normalize_url_template(url: str) -> str:
    p = urlparse(url)
    if not p.query:
        return urlunparse((p.scheme, p.netloc, p.path, p.params, "", p.fragment))
    qs = parse_qs(p.query, keep_blank_values=True)
    pairs = []
    for k in sorted(qs.keys()):
        pairs.append(f"{k}={{}}")
    new_query = "&".join(pairs)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))


def host_in_scope(url: str, scope_host: str) -> bool:
    try:
        h = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    scope = scope_host.lower().rstrip(".")
    return h == scope or h.endswith("." + scope)


def points_from_url(url: str, headers: dict[str, str], fuzz_headers: bool) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    p = urlparse(url)
    if p.query:
        qs = parse_qs(p.query, keep_blank_values=True)
        for name, values in qs.items():
            if should_skip_param(name):
                continue
            val = values[0] if values else ""
            points.append(
                InjectionPoint(
                    url=url,
                    method="GET",
                    location="query",
                    name=name,
                    baseline_value=val,
                    headers=dict(headers),
                    url_template=normalize_url_template(url),
                )
            )
    if fuzz_headers:
        for hname in FUZZ_HEADER_NAMES:
            points.append(
                InjectionPoint(
                    url=url.split("?")[0] or url,
                    method="GET",
                    location="header",
                    name=hname,
                    baseline_value=headers.get(hname, ""),
                    headers=dict(headers),
                    url_template=url.split("?")[0] or url,
                )
            )
    return points


class _FormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None
        self._in_textarea = False
        self._textarea_name: str | None = None
        self._textarea_value: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k: (v or "") for k, v in attrs}
        if tag == "form":
            action = attr.get("action") or self.base_url
            method = (attr.get("method") or "GET").upper()
            self._current = {
                "action": urljoin(self.base_url, action),
                "method": method,
                "fields": {},
            }
        elif self._current is not None and tag == "input":
            name = attr.get("name")
            if not name:
                return
            itype = (attr.get("type") or "text").lower()
            if itype in SKIP_INPUT_TYPES:
                return
            self._current["fields"][name] = attr.get("value") or ""
        elif self._current is not None and tag == "textarea":
            self._in_textarea = True
            self._textarea_name = attr.get("name")
            self._textarea_value = []
        elif self._current is not None and tag == "select":
            name = attr.get("name")
            if name:
                self._current["fields"][name] = ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "textarea" and self._current is not None and self._textarea_name:
            self._current["fields"][self._textarea_name] = "".join(self._textarea_value)
            self._in_textarea = False
            self._textarea_name = None
        elif tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def handle_data(self, data: str) -> None:
        if self._in_textarea:
            self._textarea_value.append(data)


def points_from_html(html: str, page_url: str, headers: dict[str, str]) -> list[InjectionPoint]:
    parser = _FormParser(page_url)
    try:
        parser.feed(html)
    except Exception:
        return []
    points: list[InjectionPoint] = []
    for form in parser.forms:
        action = form["action"]
        method = form["method"]
        fields: dict[str, str] = form["fields"]
        if not fields:
            continue
        if method == "GET":
            for name, val in fields.items():
                if should_skip_param(name):
                    continue
                sep = "&" if "?" in action else "?"
                test_url = f"{action}{sep}{urlencode({name: val})}"
                points.append(
                    InjectionPoint(
                        url=test_url,
                        method="GET",
                        location="query",
                        name=name,
                        baseline_value=val,
                        headers=dict(headers),
                        body=dict(fields),
                        url_template=normalize_url_template(test_url),
                    )
                )
        else:
            for name in fields:
                if should_skip_param(name):
                    continue
                points.append(
                    InjectionPoint(
                        url=action,
                        method=method,
                        location="body",
                        name=name,
                        baseline_value=fields.get(name, ""),
                        headers=dict(headers),
                        body=dict(fields),
                        url_template=action,
                    )
                )
    return points


def points_from_json_request(
    url: str,
    method: str,
    json_body: dict[str, Any],
    headers: dict[str, str],
) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    for key, val in json_body.items():
        if should_skip_param(key):
            continue
        if isinstance(val, (str, int, float, bool)) or val is None:
            points.append(
                InjectionPoint(
                    url=url,
                    method=method.upper(),
                    location="json",
                    name=key,
                    baseline_value=str(val) if val is not None else "",
                    headers=dict(headers),
                    body=dict(json_body),
                    url_template=url,
                )
            )
    return points


def parse_json_body(raw: str) -> dict[str, Any] | None:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(data, dict):
        return data
    return None


def dedupe_points(points: list[InjectionPoint]) -> list[InjectionPoint]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[InjectionPoint] = []
    for pt in points:
        if not pt.url_template:
            pt.url_template = normalize_url_template(pt.url)
        k = pt.key()
        if k in seen:
            continue
        seen.add(k)
        out.append(pt)
    return out


def extract_links(html: str, base_url: str) -> list[str]:
    hrefs = re.findall(
        r"""<a[^>]+href=["']([^"'#]+)["']""",
        html,
        re.I,
    )
    hrefs += re.findall(r"""href=["']([^"'#?][^"']*)["']""", html, re.I)
    links: list[str] = []
    seen: set[str] = set()
    for href in hrefs:
        if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        full = urljoin(base_url, href)
        clean = full.split("#")[0]
        if is_skippable_url(clean) or clean in seen:
            continue
        seen.add(clean)
        links.append(clean)
    links.extend(extract_urls_from_scripts(html, base_url))
    return links


def extract_urls_from_scripts(html: str, base_url: str) -> list[str]:
    """Rotas em JSON embutido (__NEXT_DATA__, RSC, etc.)."""
    out: list[str] = []
    seen: set[str] = set()
    p = urlparse(base_url)
    root = f"{p.scheme}://{p.netloc}"

    for m in re.finditer(r'"(?:href|url|path|route|permalink)":\s*"(/(?!/)[^"]{1,200})"', html):
        full = urljoin(root, m.group(1))
        if not is_skippable_url(full) and full not in seen:
            seen.add(full)
            out.append(full)

    for m in re.finditer(rf"https?://{re.escape(p.netloc)}[/\w\-.%]*", html, re.I):
        u = m.group(0).split('"')[0].split("\\")[0]
        if not is_skippable_url(u) and u not in seen:
            seen.add(u)
            out.append(u)

    next_data = re.search(
        r'<script[^>]*id="__NEXT_DATA__"[^>]*>(\{.*?\})</script>',
        html,
        re.DOTALL | re.I,
    )
    if next_data:
        try:
            data = json.loads(next_data.group(1))
            _walk_json_urls(data, root, out, seen)
        except json.JSONDecodeError:
            pass
    return out


def _walk_json_urls(obj: Any, root: str, out: list[str], seen: set[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("href", "url", "path", "slug", "permalink") and isinstance(v, str) and v.startswith("/"):
                full = urljoin(root, v)
                if not is_skippable_url(full) and full not in seen:
                    seen.add(full)
                    out.append(full)
            else:
                _walk_json_urls(v, root, out, seen)
    elif isinstance(obj, list):
        for item in obj[:200]:
            _walk_json_urls(item, root, out, seen)


def endpoint_base(url: str) -> str:
    """URL sem query para enfileirar parâmetros sintéticos."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", "", ""))


def points_from_path_ids(url: str, headers: dict[str, str]) -> list[InjectionPoint]:
    """Segmentos numéricos no path → ponto tipo path (product/123)."""
    points: list[InjectionPoint] = []
    p = urlparse(url)
    parts = [x for x in (p.path or "/").split("/") if x]
    for i, seg in enumerate(parts):
        if seg.isdigit() or (len(seg) >= 8 and re.fullmatch(r"[a-f0-9-]+", seg, re.I)):
            points.append(
                InjectionPoint(
                    url=url,
                    method="GET",
                    location="path",
                    name=f"segment_{i}",
                    baseline_value=seg,
                    headers=dict(headers),
                    url_template=url,
                )
            )
    return points


def synthetic_probe_points(
    urls: list[str],
    headers: dict[str, str],
    scope_host: str,
    *,
    max_endpoints: int = MAX_SYNTHETIC_ENDPOINTS,
) -> list[InjectionPoint]:
    """
    Cria ?id=1, ?page=1, etc. em rotas descobertas quando o crawl não achou parâmetros.
    Padrão de scanners: parameter discovery em endpoints vistos.
    """
    bases: list[str] = []
    seen_b: set[str] = set()
    for raw in urls:
        if not host_in_scope(raw, scope_host):
            continue
        base = endpoint_base(raw)
        if base not in seen_b:
            seen_b.add(base)
            bases.append(base)
    if not bases:
        return []

    points: list[InjectionPoint] = []
    for base in bases[:max_endpoints]:
        points.extend(points_from_path_ids(base, headers))
        existing_qs = set(parse_qs(urlparse(base).query).keys())
        added = 0
        for name, val in COMMON_PROBE_PARAMS:
            if name in existing_qs or should_skip_param(name):
                continue
            test_url = f"{base}?{urlencode({name: val})}"
            points.append(
                InjectionPoint(
                    url=test_url,
                    method="GET",
                    location="query",
                    name=name,
                    baseline_value=val,
                    headers=dict(headers),
                    url_template=normalize_url_template(test_url),
                )
            )
            added += 1
            if added >= MAX_SYNTHETIC_PARAMS_PER_URL:
                break
    return points


def collect_endpoint_urls(
    visited: set[str],
    captured_requests: list[dict[str, Any]],
    scope_host: str,
) -> list[str]:
    urls = list(visited)
    for entry in captured_requests:
        u = entry.get("url", "")
        if u and host_in_scope(u, scope_host):
            urls.append(u.split("#")[0])
    return urls
