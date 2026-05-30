"""Pipeline multi-fase: recon toolchain → crawl → mining → fuzz → dalfox/deep."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from vulndix.crawler import crawl
from vulndix.fuzzer import fuzz_points
from vulndix.integrations.registry import (
    merge_findings,
    run_dalfox_phase,
    run_deep_tools,
    run_stealth_recon,
)
from vulndix.models import Finding, ScanConfig
from vulndix.param_miner import (
    injection_points_from_mined_params,
    merge_mined_points,
    mine_params_from_samples,
    run_canary_probes,
)
from vulndix.reporter import eprint, emit_jsonl, print_summary, write_report


def run_scan_pipeline(
    config: ScanConfig,
    *,
    jsonl: bool = False,
    output_path: Path | None = None,
) -> list[Finding]:
    all_findings: list[Finding] = []

    if config.stealth_mode and config.use_toolchain:
        all_findings.extend(run_stealth_recon(config))

    try:
        points, cookies, pages_crawled, page_samples = crawl(config)
    except Exception as e:
        eprint(f"[-] Crawl falhou: {e}")
        return all_findings

    scope_host = urlparse(config.url).hostname or ""
    if config.stealth_mode or config.fuzz_tier_mode:
        mined_names = mine_params_from_samples(page_samples, scope_host)
        if mined_names:
            eprint(f"[*] Param mining: {len(mined_names)} nome(s) extraído(s) de JS/URLs")
            mined_pts = injection_points_from_mined_params(
                config.url,
                mined_names,
                config.extra_headers,
            )
            points = merge_mined_points(points, mined_pts)

    if not config.xss_marker:
        import uuid

        config.xss_marker = f"VDX_{uuid.uuid4().hex[:12]}"

    if config.stealth_mode and points:
        from vulndix.transport import build_session

        sess = build_session(config, cookies)
        marker = config.xss_marker
        hot = run_canary_probes(sess, points, config, marker)
        if hot:
            eprint(f"[*] Canário refletiu em {len(hot)} ponto(s) — prioridade XSS")
            config.hot_points = frozenset(hot)

    dast_findings = fuzz_points(
        points,
        config,
        cookies,
        jsonl=False,
        output_path=None,
        pages_crawled=pages_crawled,
        page_samples=page_samples,
        external_findings=all_findings,
        pipeline_mode=True,
    )
    all_findings = merge_findings(dast_findings)

    if config.stealth_mode and config.use_toolchain:
        all_findings = merge_findings(all_findings, run_dalfox_phase(config))

    if config.deep_scan:
        all_findings = merge_findings(all_findings, run_deep_tools(config))

    print_summary(
        all_findings,
        config,
        pages_crawled=pages_crawled,
        points_tested=len(points),
        probes_run=0,
    )
    if all_findings:
        if jsonl:
            emit_jsonl(all_findings)
        if output_path:
            write_report(
                all_findings,
                output_path,
                config,
                meta={
                    "pages_crawled": pages_crawled,
                    "injection_points": len(points),
                    "stealth_mode": config.stealth_mode,
                    "deep_scan": config.deep_scan,
                },
            )
            eprint(f"[+] Relatório salvo: {output_path}")
    elif output_path:
        eprint(f"[*] Relatório não gerado ({output_path}): nenhum achado.")

    return all_findings
