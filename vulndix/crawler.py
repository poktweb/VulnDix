from __future__ import annotations

import re
from collections import deque
from typing import Any
from urllib.parse import urlencode, urlparse
from urllib.robotparser import RobotFileParser

import requests
from playwright.sync_api import Page, sync_playwright

from vulndix.auth import apply_cookies_to_context, build_extra_http_headers, perform_login
from vulndix.discover import (
    collect_endpoint_urls,
    dedupe_points,
    extract_links,
    host_in_scope,
    normalize_url_template,
    parse_json_body,
    points_from_html,
    points_from_json_request,
    points_from_path_ids,
    points_from_url,
    should_skip_param,
    synthetic_probe_points,
)
from vulndix.filters import filter_points, is_skippable_url
from vulndix.models import InjectionPoint, PageSample, ScanConfig
from vulndix.portswigger import academy_seed_urls
from vulndix.reporter import eprint


def _load_robots(config: ScanConfig) -> RobotFileParser | None:
    if config.ignore_robots:
        return None
    p = urlparse(config.url)
    robots_url = f"{p.scheme}://{p.netloc}/robots.txt"
    rp = RobotFileParser()
    try:
        rp.set_url(robots_url)
        rp.read()
        return rp
    except Exception:
        return None


def _wait_for_spa(page: Page, config: ScanConfig) -> None:
    try:
        page.wait_for_load_state("networkidle", timeout=20_000)
    except Exception:
        pass
    if config.spa_wait_ms > 0:
        page.wait_for_timeout(config.spa_wait_ms)


def _extract_links_playwright(page: Page, base_url: str, scope_host: str) -> list[str]:
    links: list[str] = []
    seen: set[str] = set()
    try:
        hrefs: list[str] = page.evaluate(
            """() => Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(h => h && !h.startsWith('javascript:'))"""
        )
        for full in hrefs:
            clean = full.split("#")[0]
            if not host_in_scope(clean, scope_host) or is_skippable_url(clean):
                continue
            if clean not in seen:
                seen.add(clean)
                links.append(clean)
    except Exception:
        pass
    return links


def _points_from_playwright_forms(page: Page, headers: dict[str, str]) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    try:
        forms: list[dict[str, Any]] = page.evaluate(
            """() => {
                const out = [];
                for (const f of document.querySelectorAll('form')) {
                    const action = f.action || location.href;
                    const method = (f.method || 'get').toUpperCase();
                    const fields = {};
                    f.querySelectorAll('input, textarea, select').forEach(el => {
                        const name = el.name;
                        if (!name) return;
                        const t = (el.type || 'text').toLowerCase();
                        if (['submit','button','image','reset','file'].includes(t)) return;
                        fields[name] = el.value || '';
                    });
                    if (Object.keys(fields).length) out.push({action, method, fields});
                }
                return out;
            }"""
        )
        for form in forms:
            action = form.get("action") or page.url
            method = (form.get("method") or "GET").upper()
            fields: dict[str, str] = form.get("fields") or {}
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
    except Exception:
        pass
    return points


def _fetch_sitemap_urls(base_url: str, scope_host: str, limit: int = 40) -> list[str]:
    p = urlparse(base_url)
    root = f"{p.scheme}://{p.netloc}"
    urls: list[str] = []
    for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"):
        try:
            r = requests.get(
                root + path,
                timeout=12,
                headers={"User-Agent": "VulnDix-Crawler/1.0"},
                verify=True,
            )
            if r.status_code != 200:
                continue
            for loc in re.findall(r"<loc>\s*([^<]+)\s*</loc>", r.text, re.I):
                u = loc.strip()
                if host_in_scope(u, scope_host) and not is_skippable_url(u):
                    urls.append(u.split("#")[0])
                if len(urls) >= limit:
                    return urls
        except requests.RequestException:
            continue
    return urls


def crawl(
    config: ScanConfig,
) -> tuple[list[InjectionPoint], list[dict[str, Any]], int, list[PageSample]]:
    scope_host = urlparse(config.url).hostname or ""
    if not scope_host:
        raise ValueError("URL inválida — sem hostname.")

    all_points: list[InjectionPoint] = []
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()
    if config.portswigger_mode:
        for seed in academy_seed_urls(config.url):
            queue.append((seed, 0))
        eprint(f"[*] Modo PortSwigger: {len(queue)} URLs seed enfileiradas")
    if not queue or queue[0][0].split("#")[0] != config.url.split("#")[0]:
        queue.append((config.url, 0))

    for sm in _fetch_sitemap_urls(config.url, scope_host):
        if sm not in {u for u, _ in queue}:
            queue.append((sm, 1))
    if len(queue) > 1:
        eprint(f"[*] Sitemap: +{len(queue) - 1} URL(s) enfileirada(s)")

    captured_requests: list[dict[str, Any]] = []
    page_samples: list[PageSample] = []
    browser_cookies: list[dict[str, Any]] = []

    robots = _load_robots(config)
    default_headers = {"User-Agent": config.user_agent, **build_extra_http_headers(config)}
    fuzz_hdrs = config.fuzz_headers or config.portswigger_mode

    eprint(f"[*] Crawl iniciado: {config.url} (max_depth={config.max_depth}, max_pages={config.max_pages})")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=not config.verify_tls,
            extra_http_headers=build_extra_http_headers(config),
            user_agent=config.user_agent,
        )
        apply_cookies_to_context(context, config)
        page = context.new_page()

        def on_request(request: Any) -> None:
            try:
                url = request.url
                if not host_in_scope(url, scope_host):
                    return
                method = request.method
                headers = dict(request.headers)
                post_data = request.post_data
                entry: dict[str, Any] = {"url": url, "method": method, "headers": headers}
                if post_data:
                    entry["post_data"] = post_data
                    ct = headers.get("content-type", "").lower()
                    if "application/json" in ct:
                        jb = parse_json_body(post_data)
                        if jb:
                            all_points.extend(
                                points_from_json_request(url, method, jb, default_headers)
                            )
                    if "xml" in ct:
                        all_points.append(
                            InjectionPoint(
                                url=url,
                                method=method,
                                location="xml",
                                name="body",
                                baseline_value=post_data[:500] if post_data else "",
                                headers=dict(default_headers),
                                url_template=url,
                            )
                        )
                captured_requests.append(entry)
                all_points.extend(points_from_url(url, default_headers, fuzz_hdrs))
                all_points.extend(points_from_path_ids(url, default_headers))
            except Exception:
                pass

        page.on("request", on_request)
        page.goto(config.url, wait_until="domcontentloaded", timeout=60_000)
        _wait_for_spa(page, config)

        if config.login_url and config.username and config.password:
            eprint(f"[*] Login em {config.login_url}...")
            if perform_login(page, config):
                eprint("[+] Login submetido")
            else:
                eprint("[-] Login não concluído")

        while queue and len(visited) < config.max_pages:
            url, depth = queue.popleft()
            norm = url.split("#")[0]
            if norm in visited:
                continue
            if is_skippable_url(norm):
                continue
            if robots and not robots.can_fetch(config.user_agent, norm):
                eprint(f"[*] robots.txt bloqueou: {norm}")
                continue
            visited.add(norm)

            try:
                if norm != page.url.split("#")[0]:
                    page.goto(norm, wait_until="domcontentloaded", timeout=45_000)
                    _wait_for_spa(page, config)
                html = page.content()
            except Exception as e:
                eprint(f"[-] Falha ao carregar {norm}: {e}")
                continue

            page_samples.append(
                PageSample(url=norm, status=200, headers=dict(default_headers), body=html[:50_000])
            )
            all_points.extend(points_from_html(html, norm, default_headers))
            all_points.extend(points_from_url(norm, default_headers, fuzz_hdrs))
            all_points.extend(points_from_path_ids(norm, default_headers))
            all_points.extend(_points_from_playwright_forms(page, default_headers))

            if depth < config.max_depth:
                link_seen: set[str] = set()
                for link in extract_links(html, norm) + _extract_links_playwright(page, norm, scope_host):
                    clean = link.split("#")[0]
                    if (
                        host_in_scope(link, scope_host)
                        and clean not in visited
                        and clean not in link_seen
                        and not is_skippable_url(clean)
                    ):
                        link_seen.add(clean)
                        queue.append((clean, depth + 1))

            eprint(f"[*] Página {len(visited)}/{config.max_pages} depth={depth}: {norm[:100]}")

        browser_cookies = context.cookies()
        browser.close()

    injectable = sum(1 for p in all_points if p.location in ("query", "body", "json", "path"))
    if config.discover_params and injectable < 2:
        endpoints = collect_endpoint_urls(visited, captured_requests, scope_host)
        synth = synthetic_probe_points(endpoints, default_headers, scope_host)
        if synth:
            all_points.extend(synth)
            eprint(
                f"[*] Descoberta de parâmetros: +{len(synth)} ponto(s) sintéticos "
                f"(?id=, ?page=, ?productId=, … em {min(len(endpoints), 25)} rota(s))"
            )

    unique = filter_points(dedupe_points(all_points))
    eprint(
        f"[+] Crawl: {len(visited)} páginas, {len(unique)} pontos testáveis "
        f"({len(captured_requests)} requests capturados)"
    )
    return unique, browser_cookies, len(visited), page_samples
