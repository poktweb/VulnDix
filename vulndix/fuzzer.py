from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

from vulndix.detectors import detect_all
from vulndix.detectors.sqli import confirm_boolean_sqli
from vulndix.idor import scan_idor
from vulndix.passive import run_passive_checks
from vulndix.payload_updater import DEFAULT_PAYLOAD_DIR, parse_payload_lines
from vulndix.filters import filter_points
from vulndix.models import Finding, InjectionPoint, PageSample, ScanConfig, VulnType
from vulndix.portswigger import PRIORITY_PAYLOADS
from vulndix.reporter import eprint, emit_jsonl, print_summary, write_report
from vulndix.transport import (
    baseline_from_probe,
    build_curl_command,
    build_session,
    send_probe,
    verify_with_curl,
)


def _order_payloads(cat: VulnType, lines: list[str], limit: int) -> list[str]:
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
    return ordered[:limit]


def load_payloads(config: ScanConfig) -> dict[VulnType, list[str]]:
    base = Path(config.payload_dir) if config.payload_dir else DEFAULT_PAYLOAD_DIR
    out: dict[VulnType, list[str]] = {}
    for cat in config.categories:
        if cat in ("info", "clickjacking", "csrf", "cors", "idor"):
            if cat == "idor":
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
            out[cat] = _order_payloads(cat, lines, config.max_payloads)
    return out


def prepare_payload(payload: str, config: ScanConfig) -> str:
    if "{{MARKER}}" in payload and config.xss_marker:
        return payload.replace("{{MARKER}}", config.xss_marker)
    return payload


def fuzz_points(
    points: list[InjectionPoint],
    config: ScanConfig,
    browser_cookies: list[dict] | None = None,
    *,
    jsonl: bool = False,
    output_path: Path | None = None,
    pages_crawled: int = 0,
    page_samples: list[PageSample] | None = None,
) -> list[Finding]:
    if not config.xss_marker:
        config.xss_marker = f"VULNDIX_{uuid.uuid4().hex[:12]}"

    from urllib.parse import urlparse

    scope_host = urlparse(config.url).hostname or ""

    raw_count = len(points)
    points = filter_points(points)
    if raw_count != len(points):
        eprint(f"[*] Ignorados {raw_count - len(points)} parâmetro(s) de framework/analytics")

    session = build_session(config, browser_cookies)
    payloads_map = load_payloads(config)
    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    lock = Lock()

    passive = run_passive_checks(page_samples or [], config)
    findings.extend(passive)
    for pf in passive:
        eprint(f"[+] {pf.type.upper()} (passivo) — {pf.evidence[:80]}")

    idor_findings = scan_idor(session, points, config)
    findings.extend(idor_findings)

    eprint(f"[*] Marcador XSS (interno): {config.xss_marker}")
    eprint(f"[*] Pontos de injeção: {len(points)}")
    for cat, pls in payloads_map.items():
        eprint(f"[*] Payloads {cat}: {len(pls)}")

    def work(point: InjectionPoint, vuln_type: VulnType, payload: str) -> Finding | None:
        time.sleep(config.delay_ms / 1000.0)
        prepared = prepare_payload(payload, config)
        baseline_probe = send_probe(session, point, point.baseline_value or "")
        baseline = baseline_from_probe(baseline_probe)
        probe = send_probe(session, point, prepared)
        result = detect_all(
            vuln_type,
            point,
            payload,
            baseline,
            probe,
            xss_marker=config.xss_marker,
            scope_host=scope_host,
        )
        if vuln_type == "sqli":
            confirmed = confirm_boolean_sqli(session, point, prepared, baseline, probe)
            if confirmed:
                result = confirmed
        if not result:
            return None
        if config.verify_curl:
            result.curl = build_curl_command(session, point, prepared, not config.verify_tls)
            verify_with_curl(result.curl)
        sig = (result.type, result.param, point.url_template or point.url, result.payload)
        with lock:
            if sig in seen:
                return None
            seen.add(sig)
            findings.append(result)
        eprint(f"[+] {result.type.upper()} {result.param} — {result.evidence[:90]}")
        return result

    tasks: list[tuple[InjectionPoint, VulnType, str]] = []
    for point in points:
        for vuln_type in config.categories:
            if vuln_type in ("info", "clickjacking", "csrf", "cors", "idor"):
                continue
            for payload in payloads_map.get(vuln_type, []):
                tasks.append((point, vuln_type, payload))

    eprint(f"[*] Total de probes: {len(tasks)} (threads={config.threads})")

    with ThreadPoolExecutor(max_workers=max(1, config.threads)) as ex:
        futs = [ex.submit(work, pt, vt, pl) for pt, vt, pl in tasks]
        for fut in as_completed(futs):
            try:
                fut.result()
            except Exception as e:
                eprint(f"[-] Erro no fuzz: {e}")

    print_summary(
        findings,
        config,
        pages_crawled=pages_crawled,
        points_tested=len(points),
        probes_run=len(tasks),
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
                    "probes": len(tasks),
                    "portswigger_mode": config.portswigger_mode,
                },
            )
            eprint(f"[+] Relatório salvo: {output_path}")
    else:
        if output_path:
            eprint(f"[*] Relatório não gerado ({output_path}): nenhum achado na varredura.")

    return findings
