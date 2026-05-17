from __future__ import annotations

import json
from collections import deque
from typing import Any
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

from playwright.sync_api import sync_playwright

from vulndix.auth import apply_cookies_to_context, build_extra_http_headers, perform_login
from vulndix.discover import (
    dedupe_points,
    extract_links,
    host_in_scope,
    parse_json_body,
    points_from_html,
    points_from_json_request,
    points_from_url,
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
            except Exception:
                pass

        page.on("request", on_request)
        page.goto(config.url, wait_until="domcontentloaded", timeout=60_000)

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
                html = page.content()
            except Exception as e:
                eprint(f"[-] Falha ao carregar {norm}: {e}")
                continue

            page_samples.append(
                PageSample(url=norm, status=200, headers=dict(default_headers), body=html[:50_000])
            )
            all_points.extend(points_from_html(html, norm, default_headers))
            all_points.extend(points_from_url(norm, default_headers, fuzz_hdrs))

            if depth < config.max_depth:
                for link in extract_links(html, norm):
                    clean = link.split("#")[0]
                    if (
                        host_in_scope(link, scope_host)
                        and clean not in visited
                        and not is_skippable_url(clean)
                    ):
                        queue.append((clean, depth + 1))

            eprint(f"[*] Página {len(visited)}/{config.max_pages} depth={depth}: {norm[:100]}")

        browser_cookies = context.cookies()
        browser.close()

    unique = filter_points(dedupe_points(all_points))
    eprint(
        f"[+] Crawl: {len(visited)} páginas, {len(unique)} pontos testáveis "
        f"({len(captured_requests)} requests; _rsc/utm ignorados)"
    )
    return unique, browser_cookies, len(visited), page_samples
