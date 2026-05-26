#!/usr/bin/env python3
"""
VulnDix — scanner DAST (PortSwigger Academy + alvos autorizados).

Exemplo scan completo:
  python vulndix.py -u https://alvo.com/ --all -o report.json --i-understand
Exemplo lab PortSwigger:
  python vulndix.py -u https://SEU-LAB.web-security-academy.net/ --portswigger -o report.json --i-understand
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vulndix.crawler import crawl
from vulndix.fuzzer import fuzz_points
from vulndix.wordlist_fuzz import (
    FUZZ_TOKEN,
    load_wordlist,
    parse_fuzz_target,
    resolve_wordlist_path,
    run_wordlist_fuzz,
)
from vulndix.models import ScanConfig, VulnType
from vulndix.payload_updater import ensure_payloads, update_payloads
from vulndix.portswigger import ALL_SCAN_CATEGORIES, PORTSWIGGER_CATEGORIES
from vulndix.reporter import eprint

LEGAL_BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║  VulnDix — scanner DAST                                         ║
║  Use SOMENTE em alvos com autorização explícita (pentest/BB).   ║
║  O autor não se responsabiliza por uso indevido.                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

ALL_CATEGORIES: tuple[VulnType, ...] = tuple(sorted(ALL_SCAN_CATEGORIES))  # type: ignore[arg-type]


def parse_categories(raw: str | None) -> frozenset[VulnType]:
    if not raw:
        return frozenset(
            {
                "xss",
                "sqli",
                "lfi",
                "ssti",
                "cmdi",
                "redirect",
                "traversal",
            }
        )
    parts = {p.strip().lower() for p in raw.split(",") if p.strip()}
    unknown = parts - set(ALL_CATEGORIES)
    if unknown:
        raise ValueError(f"Categorias desconhecidas: {', '.join(sorted(unknown))}")
    return frozenset(parts)  # type: ignore[return-value]


def parse_match_codes(raw: str | None) -> frozenset[int]:
    if not raw:
        from vulndix.wordlist_fuzz import DEFAULT_MATCH_CODES

        return DEFAULT_MATCH_CODES
    codes: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            codes.add(int(part))
        except ValueError as e:
            raise ValueError(f"Código HTTP inválido em --match-codes: {part!r}") from e
    if not codes:
        raise ValueError("--match-codes não pode ser vazio.")
    return frozenset(codes)


def parse_header(raw: str) -> tuple[str, str]:
    if ":" not in raw:
        raise ValueError(f"Header inválido (use Nome: Valor): {raw!r}")
    name, val = raw.split(":", 1)
    return name.strip(), val.strip()


def resolve_categories(args: argparse.Namespace) -> frozenset[VulnType]:
    if args.categories and (args.all or args.portswigger):
        raise ValueError(
            "Use apenas um preset: --all ou --portswigger, ou --categories (não combine)."
        )
    if args.all or args.portswigger:
        return ALL_SCAN_CATEGORIES
    return parse_categories(args.categories)


def apply_scan_presets(args: argparse.Namespace) -> None:
    """Ajusta limites padrão quando --all ou --portswigger estão ativos."""
    if args.all or args.portswigger:
        if args.max_payloads == 30:
            args.max_payloads = 8
        if args.delay_ms == 100:
            args.delay_ms = 0
        if args.threads == 5:
            args.threads = 30
    if args.portswigger and args.max_pages == 150:
        args.max_pages = 40


def build_config(args: argparse.Namespace) -> ScanConfig:
    extra_headers: dict[str, str] = {}
    for h in args.header or []:
        k, v = parse_header(h)
        extra_headers[k] = v

    categories = resolve_categories(args)
    full_scan = args.all or args.portswigger

    return ScanConfig(
        url=args.url or "",
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        ignore_robots=args.ignore_robots or full_scan,
        verify_tls=not args.insecure,
        fuzz_headers=args.fuzz_headers or full_scan,
        portswigger_mode=args.portswigger,
        fast_fuzz=full_scan,
        probe_timeout_s=8.0 if full_scan else 12.0,
        probe_max_body_bytes=98304,
        fuzz_category_cap=6 if full_scan else 0,
        categories=categories,
        max_payloads=args.max_payloads,
        delay_ms=args.delay_ms,
        threads=args.threads,
        verify_curl=not args.no_verify_curl and not full_scan,
        payload_dir=args.payload_dir,
        user_agent=args.user_agent,
        login_url=args.login_url,
        username=args.user,
        password=args.password,
        login_user_selector=args.login_user_selector,
        login_pass_selector=args.login_pass_selector,
        login_submit_selector=args.login_submit_selector,
        cookies=list(args.cookie or []),
        extra_headers=extra_headers,
        token=args.token,
        wordlist_path=args.wordlist,
        wordlist_method=args.fuzz_method,
        fuzz_match_codes=parse_match_codes(args.match_codes),
        fuzz_filter_baseline=not args.no_fuzz_baseline_filter,
        wordlist_max_lines=args.wordlist_max or 0,
        discover_params=not args.no_discover_params,
        spa_wait_ms=args.spa_wait_ms,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="VulnDix — DAST com suporte PortSwigger Web Security Academy.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Scan completo: --all | Labs Academy: --portswigger | Doc: Comandos.txt",
    )
    p.add_argument(
        "-u",
        "--url",
        default=None,
        help=(
            "URL alvo ou template com FUZZ: "
            "https://site/FUZZ (dirs), https://FUZZ.site.com ou FUZZ.site.com (subdomínios)."
        ),
    )
    p.add_argument(
        "-w",
        "--wordlist",
        default=None,
        metavar="FILE",
        help="Wordlist para fuzz de dirs/subdomínios (ou atalho: common-dirs, common-subdomains).",
    )
    p.add_argument(
        "--fuzz-method",
        default="GET",
        choices=("GET", "HEAD"),
        help="Método HTTP no fuzz com wordlist.",
    )
    p.add_argument(
        "--match-codes",
        default=None,
        metavar="CODES",
        help="Códigos HTTP a exibir (padrão: 200,204,301,302,307,401,403).",
    )
    p.add_argument(
        "--no-fuzz-baseline-filter",
        action="store_true",
        help="Não ocultar respostas iguais à baseline (404 genérico).",
    )
    p.add_argument(
        "--wordlist-max",
        type=int,
        default=0,
        metavar="N",
        help="Limitar linhas da wordlist (0 = todas).",
    )
    p.add_argument(
        "--all",
        action="store_true",
        help="Testa todas as falhas (21 categorias) sem listar --categories; fuzz de headers ativo.",
    )
    p.add_argument(
        "--portswigger",
        action="store_true",
        help="Preset Academy: igual --all + rotas típicas dos labs (/filter, /product, …).",
    )
    p.add_argument("--update-payloads", action="store_true", help="Só baixa payloads e encerra.")
    p.add_argument("--refresh-payloads", action="store_true", help="Força download de payloads.")
    p.add_argument("--skip-payload-sync", action="store_true", help="Não baixa da internet.")
    p.add_argument("--payloads-cache-max", type=int, default=500, metavar="N")
    p.add_argument("--i-understand", action="store_true", help="Autorização confirmada.")
    p.add_argument("--max-depth", type=int, default=3)
    p.add_argument("--max-pages", type=int, default=150)
    p.add_argument("--ignore-robots", action="store_true")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--fuzz-headers", action="store_true")
    p.add_argument(
        "--no-discover-params",
        action="store_true",
        help="Não criar ?id=, ?page=, etc. quando o crawl não achar parâmetros (SPAs).",
    )
    p.add_argument(
        "--spa-wait-ms",
        type=int,
        default=2500,
        metavar="MS",
        help="Espera extra após cada página para JS/API (0=desliga).",
    )
    p.add_argument("--categories", default=None, help=f"{','.join(ALL_CATEGORIES)}")
    p.add_argument("--max-payloads", type=int, default=30)
    p.add_argument("--delay-ms", type=int, default=100)
    p.add_argument("-j", "--threads", type=int, default=5, help="Paralelismo do fuzz ( --all usa 20 ).")
    p.add_argument("--no-verify-curl", action="store_true")
    p.add_argument("--payload-dir", default=None)
    p.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (compatible; VulnDix/1.0; +https://example.local)",
    )
    p.add_argument("--jsonl", action="store_true")
    p.add_argument("-o", "--output", default=None, metavar="FILE")
    p.add_argument("--crawl-only", action="store_true")
    p.add_argument("--login-url", default=None)
    p.add_argument("--user", default=None)
    p.add_argument("--password", default=None)
    p.add_argument("--login-user-selector", default=None)
    p.add_argument("--login-pass-selector", default=None)
    p.add_argument("--login-submit-selector", default=None)
    p.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE")
    p.add_argument("--header", action="append", default=[], metavar="Name: Value")
    p.add_argument("--token", default=None)
    return p


def main() -> int:
    args = build_arg_parser().parse_args()
    print(LEGAL_BANNER, file=sys.stderr)

    apply_scan_presets(args)

    if args.update_payloads:
        if args.all or args.portswigger:
            cats = ALL_SCAN_CATEGORIES
        elif args.categories:
            cats = parse_categories(args.categories)
        else:
            cats = None
        dest = Path(args.payload_dir) if args.payload_dir else None
        counts = update_payloads(dest, cats, max_per_category=args.payloads_cache_max)
        return 0 if sum(counts.values()) > 0 else 1

    if not args.url and not args.update_payloads:
        eprint("[-] Informe -u/--url ou use --update-payloads.")
        return 2

    wordlist_mode = bool(args.wordlist) or (
        args.url and FUZZ_TOKEN in args.url.upper()
    )
    if wordlist_mode:
        if not args.i_understand:
            eprint("[-] Adicione --i-understand para confirmar autorização no alvo.")
            return 2
        if not args.wordlist:
            eprint("[-] Fuzz com FUZZ exige -w/--wordlist.")
            return 2
        if not args.url:
            eprint("[-] Informe -u com FUZZ na URL.")
            return 2
        try:
            config = build_config(args)
            wl_path = resolve_wordlist_path(args.wordlist)
            target = parse_fuzz_target(args.url)
            words = load_wordlist(wl_path, max_lines=config.wordlist_max_lines)
        except (ValueError, FileNotFoundError) as e:
            eprint(f"[-] {e}")
            return 2
        eprint(f"[*] Modo wordlist ({target.mode}): {len(words)} entradas de {wl_path.name}")
        out_path = Path(args.output) if args.output else None
        run_wordlist_fuzz(
            config,
            target,
            words,
            output_path=out_path,
            jsonl=args.jsonl,
        )
        return 0

    if not args.url:
        eprint("[-] Informe -u/--url ou use --update-payloads.")
        return 2
    if not args.i_understand:
        eprint("[-] Adicione --i-understand para confirmar autorização no alvo.")
        return 2
    try:
        config = build_config(args)
    except ValueError as e:
        eprint(f"[-] {e}")
        return 2

    if args.all and not args.portswigger:
        eprint(
            "[*] Modo All: "
            + ", ".join(sorted(config.categories))
        )
    if args.portswigger:
        eprint("[*] Modo PortSwigger: modo All + rotas típicas dos labs Academy")

    if not args.crawl_only and not args.skip_payload_sync:
        payload_dest = Path(args.payload_dir) if args.payload_dir else None
        ensure_payloads(
            payload_dest,
            config.categories,
            max_per_category=args.payloads_cache_max,
            force=args.refresh_payloads,
        )
    elif args.skip_payload_sync:
        eprint("[*] Download de payloads desativado (--skip-payload-sync).")

    try:
        points, cookies, pages_crawled, page_samples = crawl(config)
    except Exception as e:
        eprint(f"[-] Crawl falhou: {e}")
        return 1

    if args.crawl_only:
        for pt in points:
            print(
                json.dumps(
                    {
                        "url": pt.url,
                        "method": pt.method,
                        "location": pt.location,
                        "name": pt.name,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        eprint(f"[+] {len(points)} pontos listados (crawl-only)")
        return 0

    out_path = Path(args.output) if args.output else None
    if not out_path and not args.jsonl:
        eprint("[*] Dica: use -o report.json para salvar o relatório completo.")

    fuzz_points(
        points,
        config,
        cookies,
        jsonl=args.jsonl,
        output_path=out_path,
        pages_crawled=pages_crawled,
        page_samples=page_samples,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
