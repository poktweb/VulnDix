from __future__ import annotations

from typing import Any

from playwright.sync_api import BrowserContext, Page

from vulndix.models import ScanConfig


def build_extra_http_headers(config: ScanConfig) -> dict[str, str]:
    headers = dict(config.extra_headers)
    if config.token:
        headers["Authorization"] = (
            config.token
            if config.token.lower().startswith("bearer ")
            else f"Bearer {config.token}"
        )
    return headers


def apply_cookies_to_context(context: BrowserContext, config: ScanConfig) -> None:
    if not config.cookies:
        return
    cookies: list[dict[str, Any]] = []
    for raw in config.cookies:
        parts = raw.split("=", 1)
        if len(parts) != 2:
            continue
        name, value = parts[0].strip(), parts[1].strip()
        if not name:
            continue
        cookies.append(
            {
                "name": name,
                "value": value,
                "url": config.url,
                "path": "/",
            }
        )
    if cookies:
        context.add_cookies(cookies)


def perform_login(page: Page, config: ScanConfig) -> bool:
    if not config.login_url or not config.username or not config.password:
        return False
    page.goto(config.login_url, wait_until="domcontentloaded", timeout=60_000)
    user_sel = config.login_user_selector
    pass_sel = config.login_pass_selector
    submit_sel = config.login_submit_selector

    if not user_sel:
        for sel in ('input[name="username"]', 'input[name="user"]', 'input[type="email"]', 'input[type="text"]'):
            if page.locator(sel).count() > 0:
                user_sel = sel
                break
        if not user_sel:
            user_sel = "input:not([type=password]):not([type=hidden]):not([type=submit])"

    if not pass_sel:
        pass_sel = 'input[type="password"]'

    page.fill(user_sel, config.username)
    page.fill(pass_sel, config.password)

    if submit_sel:
        page.click(submit_sel)
    else:
        submitted = False
        for sel in ('button[type="submit"]', 'input[type="submit"]', 'button:has-text("Login")', 'button:has-text("Entrar")'):
            if page.locator(sel).count() > 0:
                page.click(sel)
                submitted = True
                break
        if not submitted:
            page.locator(pass_sel).press("Enter")

    try:
        page.wait_for_load_state("networkidle", timeout=15_000)
    except Exception:
        pass
    return True
