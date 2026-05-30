from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from threading import Lock

from vulndix.detectors import detect_all
from vulndix.detectors.sqli import confirm_boolean_sqli
from vulndix.fuzz_plan import (
    categories_for_point,
    dedupe_injection_points,
    estimate_fuzz_tasks,
    estimate_fuzz_tasks_tiered,
    filter_points_for_fast_fuzz,
    payloads_for_tier,
    probe_has_anomaly,
    prioritize_points,
)
from vulndix.stealth import StealthController, jitter_delay
from vulndix.api_probe import scan_exposed_apis
from vulndix.idor import scan_idor
from vulndix.passive import run_passive_checks
from vulndix.payload_updater import DEFAULT_PAYLOAD_DIR, parse_payload_lines
from vulndix.filters import filter_points
from vulndix.models import (
    BaselineResponse,
    Finding,
    InjectionPoint,
    PageSample,
    ScanConfig,
    VulnType,
)
from vulndix.portswigger import PRIORITY_PAYLOADS
from vulndix.reporter import eprint, emit_jsonl, print_summary, write_report
from vulndix.transport import (
    baseline_from_probe,
    build_curl_command,
    build_session,
    send_probe,
    verify_with_curl,
)


def _order_payloads(
    cat: VulnType, lines: list[str], limit: int, *, fast: bool = False
) -> list[str]:
    priority = PRIORITY_PAYLOADS.get(cat, ())
    ordered: list[str] = []
    seen: set[str] = set()
    for p in priority:
        if p in lines and p not in seen:
            ordered.append(p)
            seen.add(p)
    for line in lines:
        if line not in seen:
            ordered.append(line)
            seen.add(line)
    if fast:
        cap = min(limit, max(5, len(priority) + 2))
        return ordered[:cap]
    return ordered[:limit]


def load_payloads(config: ScanConfig) -> dict[VulnType, list[str]]:
    base = Path(config.payload_dir) if config.payload_dir else DEFAULT_PAYLOAD_DIR
    out: dict[VulnType, list[str]] = {}
    for cat in config.categories:
        if cat in (
            "info",
            "clickjacking",
            "csrf",
            "cors",
            "idor",
            "sec_headers",
            "cookie_sec",
            "api_exposed",
        ):
            if cat in ("idor", "api_exposed"):
                continue
            seeds = PRIORITY_PAYLOADS.get(cat, ())
            if seeds:
                out[cat] = list(seeds)
            continue
        path = base / f"{cat}.txt"
        if path.is_file():
            lines = parse_payload_lines(path.read_text(encoding="utf-8"))
        else:
            lines = list(PRIORITY_PAYLOADS.get(cat, ()))
        if lines:
            out[cat] = _order_payloads(
                cat, lines, config.max_payloads, fast=config.fast_fuzz
            )
    return out


def prepare_payload(payload: str, config: ScanConfig) -> str:
    if "{{MARKER}}" in payload and config.xss_marker:
        return payload.replace("{{MARKER}}", config.xss_marker)
    return payload


def _collect_baselines(
    points: list[InjectionPoint],
    config: ScanConfig,
    browser_cookies: list[dict] | None,
) -> dict[tuple[str, str, str, str], BaselineResponse]:
    cache: dict[tuple[str, str, str, str], BaselineResponse] = {}
    timeout = config.probe_timeout_s
    max_body = config.probe_max_body_bytes
    workers = min(config.threads, max(4, min(24, len(points) // 4 + 4)))
    thread_local = threading.local()

    def session_for_thread() -> object:
        if not getattr(thread_local, "session", None):
            thread_local.session = build_session(config, browser_cookies, pool_size=8)
        return thread_local.session

    def one(pt: InjectionPoint) -> tuple[tuple[str, str, str, str], BaselineResponse]:
        sess = session_for_thread()
        probe = send_probe(
            sess,
            pt,
            pt.baseline_value or "",
            timeout=timeout,
            max_body_bytes=max_body,
        )
        return pt.key(), baseline_from_probe(probe)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(one, pt) for pt in points]
        done = 0
        for fut in futs:
            key, baseline = fut.result()
            cache[key] = baseline
            done += 1
            if done == len(points) or done % 25 == 0:
                eprint(f"[*] Baselines: {done}/{len(points)}")
    return cache


def fuzz_points(
    points: list[InjectionPoint],
    config: ScanConfig,
    browser_cookies: list[dict] | None = None,
    *,
    jsonl: bool = False,
    output_path: Path | None = None,
    pages_crawled: int = 0,
    page_samples: list[PageSample] | None = None,
    external_findings: list[Finding] | None = None,
    pipeline_mode: bool = False,
) -> list[Finding]:
    if not config.xss_marker:
        config.xss_marker = f"VULNDIX_{uuid.uuid4().hex[:12]}"

    from urllib.parse import urlparse

    scope_host = urlparse(config.url).hostname or ""

    raw_count = len(points)
    points = dedupe_injection_points(filter_points(points))
    if config.fast_fuzz:
        before = len(points)
        points = filter_points_for_fast_fuzz(points)
        if before != len(points):
            eprint(f"[*] Modo rápido: {before - len(points)} ponto(s) de header omitidos")

    dupes = raw_count - len(points)
    if dupes > 0:
        eprint(f"[*] {dupes} ponto(s) duplicado(s) ou de framework removidos")

    points = prioritize_points(points)

    session = build_session(config, browser_cookies, pool_size=config.threads * 2)
    thread_local = threading.local()

    def thread_session():
        if not getattr(thread_local, "session", None):
            thread_local.session = build_session(
                config, browser_cookies, pool_size=8
            )
        return thread_local.session

    payloads_map = load_payloads(config)
    findings: list[Finding] = list(external_findings or [])
    seen: set[tuple[str, str, str, str]] = {
        (f.type, f.param, f.endpoint, f.payload) for f in findings
    }
    skip_pair: set[tuple[tuple[str, str, str, str], str]] = set()
    tier2_allowed: set[tuple[tuple[str, str, str, str], str]] = set()
    lock = Lock()
    probes_done = 0

    stealth_ctl: StealthController | None = None
    if config.stealth_mode:
        stealth_ctl = StealthController(base_delay_ms=config.delay_ms)

    passive = run_passive_checks(page_samples or [], config)
    findings.extend(passive)
    passive_urls: set[str] = set()
    for pf in passive:
        if pf.type == "clickjacking" and pf.endpoint in passive_urls:
            continue
        passive_urls.add(pf.endpoint)
        eprint(f"[+] {pf.type.upper()} (passivo) — {pf.evidence[:80]}")

    idor_findings = scan_idor(session, points, config)
    findings.extend(idor_findings)

    api_findings = scan_exposed_apis(config, browser_cookies)
    findings.extend(api_findings)

    eprint(f"[*] Marcador XSS (interno): {config.xss_marker}")
    eprint(f"[*] Pontos de injeção: {len(points)}")
    for cat, pls in payloads_map.items():
        eprint(f"[*] Payloads {cat}: {len(pls)}")

    eprint(f"[*] Medindo baselines ({len(points)} pontos)...")
    baseline_cache = _collect_baselines(points, config, browser_cookies)

    timeout = config.probe_timeout_s
    max_body = config.probe_max_body_bytes
    per_thread_delay = (
        0.0
        if config.stealth_mode and stealth_ctl
        else config.delay_ms / 1000.0 / max(1, config.threads)
    )
    cat_cap = config.fuzz_category_cap if config.fast_fuzz else 0
    effective_threads = (
        stealth_ctl.apply_thread_cap(config.threads) if stealth_ctl else config.threads
    )

    def run_probe(
        point: InjectionPoint, vuln_type: VulnType, payload: str
    ) -> Finding | None:
        nonlocal probes_done

        if stealth_ctl:
            stealth_ctl.wait_before_request()
        elif per_thread_delay > 0:
            time.sleep(per_thread_delay)
        elif config.jitter_ms > 0:
            time.sleep(jitter_delay(config.jitter_ms))

        prepared = prepare_payload(payload, config)
        baseline = baseline_cache[point.key()]
        sess = thread_session()
        probe = send_probe(
            sess,
            point,
            prepared,
            timeout=timeout,
            max_body_bytes=max_body,
        )
        if stealth_ctl:
            stealth_ctl.record_response(probe.status)
        with lock:
            probes_done += 1

        pair = (point.key(), vuln_type)
        if config.fuzz_tier_mode and probe_has_anomaly(baseline, probe):
            tier2_allowed.add(pair)

        result = detect_all(
            vuln_type,
            point,
            payload,
            baseline,
            probe,
            xss_marker=config.xss_marker,
            scope_host=scope_host,
        )
        if vuln_type == "sqli" and result:
            confirmed = confirm_boolean_sqli(sess, point, prepared, baseline, probe)
            if confirmed:
                result = confirmed
        if not result:
            return None

        if config.verify_curl:
            result.curl = build_curl_command(sess, point, prepared, not config.verify_tls)
            verify_with_curl(result.curl)

        sig = (result.type, result.param, point.url_template or point.url, result.payload)
        with lock:
            if sig in seen:
                return None
            seen.add(sig)
            if result.confidence in ("high", "medium"):
                skip_pair.add((point.key(), vuln_type))
            findings.append(result)
        eprint(f"[+] {result.type.upper()} {result.param} — {result.evidence[:90]}")
        return result

    def iter_payloads(vuln_type: VulnType, full_list: list[str]) -> list[tuple[int, str]]:
        if not config.fuzz_tier_mode:
            return [(1, p) for p in full_list]
        ordered: list[tuple[int, str]] = []
        for tier in (0, 1):
            ordered.extend(
                (tier, p)
                for p in payloads_for_tier(
                    vuln_type, full_list, tier, fast=config.fast_fuzz
                )
            )
        return ordered

    def fuzz_one_point(point: InjectionPoint) -> None:
        if config.fast_fuzz:
            cats = categories_for_point(
                point, config.categories, category_cap=cat_cap
            )
        else:
            cats = tuple(
                c
                for c in categories_for_point(point, config.categories, category_cap=0)
            )
        if config.hot_points and point.key() in config.hot_points:
            cats = tuple(c for c in ("xss", "sqli") if c in cats) + tuple(
                c for c in cats if c not in ("xss", "sqli")
            )
        for vuln_type in cats:
            pair = (point.key(), vuln_type)
            with lock:
                if pair in skip_pair:
                    continue
            full_list = payloads_map.get(vuln_type, ())
            tiered = iter_payloads(vuln_type, full_list)
            for tier, payload in tiered:
                if tier == 2:
                    with lock:
                        if pair not in tier2_allowed:
                            continue
                with lock:
                    if pair in skip_pair:
                        break
                try:
                    finding = run_probe(point, vuln_type, payload)
                    if (
                        config.fuzz_tier_mode
                        and config.stealth_mode
                        and tier >= 1
                        and not finding
                    ):
                        with lock:
                            if pair not in tier2_allowed:
                                break
                except Exception as e:
                    eprint(f"[-] Erro no fuzz ({point.name}/{vuln_type}): {e}")
                    break
            if config.fuzz_tier_mode:
                with lock:
                    allow_t2 = pair in tier2_allowed and pair not in skip_pair
                if allow_t2:
                    for payload in payloads_for_tier(
                        vuln_type, full_list, 2, fast=config.fast_fuzz
                    ):
                        with lock:
                            if pair in skip_pair:
                                break
                        try:
                            run_probe(point, vuln_type, payload)
                        except Exception as e:
                            eprint(f"[-] Erro no fuzz tier2 ({point.name}): {e}")
                            break

    naive = 0
    for point in points:
        for vuln_type in config.categories:
            if vuln_type in (
                "info",
                "clickjacking",
                "csrf",
                "cors",
                "idor",
                "sec_headers",
                "cookie_sec",
                "api_exposed",
            ):
                continue
            naive += len(payloads_map.get(vuln_type, ()))

    if config.fuzz_tier_mode:
        planned = estimate_fuzz_tasks_tiered(points, config, payloads_map)
    else:
        planned = estimate_fuzz_tasks(points, config, payloads_map)
    saved_plan = naive - planned if naive > planned else 0

    eprint(
        f"[*] Plano: até {planned} probes"
        + (f" ({saved_plan} a menos que varredura ingênua)" if saved_plan else "")
        + f" | threads={effective_threads} | timeout={timeout}s | body≤{max_body // 1024}KB"
    )
    if config.fast_fuzz:
        eprint(
            "[*] Turbo: categorias por parâmetro, cap "
            f"{cat_cap or 'off'}, parada ao achar falha na categoria"
        )
    if config.fuzz_tier_mode:
        eprint("[*] Fuzz em tiers: canário → prioridade → resto (se anomalia)")

    t0 = time.perf_counter()
    max_inflight = max(16, min(len(points), effective_threads * 2))

    with ThreadPoolExecutor(max_workers=max(1, effective_threads)) as ex:
        pending = {ex.submit(fuzz_one_point, pt) for pt in points}
        last_log = 0
        progress_step = max(50, planned // 25 or 50)
        while pending:
            done_set, pending = wait(pending, return_when=FIRST_COMPLETED)
            for fut in done_set:
                try:
                    fut.result()
                except Exception as e:
                    eprint(f"[-] Erro no ponto: {e}")
            with lock:
                pd = probes_done
            if pd - last_log >= progress_step or not pending:
                last_log = pd
                elapsed = time.perf_counter() - t0
                rate = pd / elapsed if elapsed > 0 else 0.0
                remain = max(0, planned - pd)
                eta_s = remain / rate if rate > 0 else 0.0
                pct = min(100.0, 100.0 * pd / planned) if planned else 100.0
                eprint(
                    f"[*] Fuzz: {pd} probes (~{pct:.0f}% do plano) "
                    f"— {rate:.1f}/s, ETA ~{max(0, int(eta_s // 60))} min"
                )

    elapsed = time.perf_counter() - t0
    with lock:
        total_probes = probes_done
    eprint(
        f"[*] Fuzz finalizado: {total_probes} probes em {elapsed:.1f}s "
        f"({total_probes / elapsed:.1f}/s)" if elapsed > 0 else ""
    )

    if not pipeline_mode:
        print_summary(
            findings,
            config,
            pages_crawled=pages_crawled,
            points_tested=len(points),
            probes_run=total_probes,
        )

        if findings:
            if jsonl:
                emit_jsonl(findings)
            if output_path:
                write_report(
                    findings,
                    output_path,
                    config,
                    meta={
                        "pages_crawled": pages_crawled,
                        "injection_points": len(points),
                        "probes": total_probes,
                        "portswigger_mode": config.portswigger_mode,
                        "fast_fuzz": config.fast_fuzz,
                        "stealth_mode": config.stealth_mode,
                    },
                )
                eprint(f"[+] Relatório salvo: {output_path}")
        else:
            if output_path:
                eprint(f"[*] Relatório não gerado ({output_path}): nenhum achado na varredura.")

    return findings
