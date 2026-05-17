from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests

from vulndix.models import VulnType
from vulndix.reporter import eprint

DEFAULT_PAYLOAD_DIR = Path(__file__).resolve().parent / "payloads"
MANIFEST_NAME = "sources.manifest.txt"
STAMP_FILE = ".payloads_synced"
VERSION_FILE = ".payloads_version"
PAYLOADS_TOOL_VERSION = 3
# Mínimo de payloads por categoria para considerar "já baixado"
MIN_PAYLOADS_READY = 15
MIN_PAYLOADS_READY_SMALL = 5  # redirect, ssti (menos fontes online)
SMALL_CATEGORIES = frozenset({"redirect", "ssti"})
# Sem arquivo de fuzz (só detectores passivos / headers fixos)
PASSIVE_SCAN_CATEGORIES = frozenset({"idor", "cors", "csrf", "clickjacking", "info"})
# Apenas seeds locais (sem listas remotas grandes)
SEED_ONLY_CATEGORIES = frozenset({"host_header"})

BLOCKED_PATTERNS = re.compile(
    r"(?i)(drop\s+table|delete\s+from|truncate\s+table|;\s*shutdown|rm\s+-rf\s+/|format\s+c:)"
)

MAX_LINE_LEN = 512
CODE_FENCE_RE = re.compile(r"```[\w]*\n(.*?)```", re.DOTALL | re.IGNORECASE)
INLINE_CODE_RE = re.compile(r"`([^`\n]{2,200})`")


@dataclass(frozen=True)
class PayloadSource:
    url: str
    label: str
    markdown: bool = False


# GitHub raw — PayloadsAllTheThings (swisskyrepo) + SecLists + fuzzdb
PAYLOAD_SOURCES: dict[VulnType, tuple[PayloadSource, ...]] = {
    "xss": (
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/XSS_Polyglots.txt",
            "PAT/XSS_Polyglots",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/BruteXSS.txt",
            "PAT/BruteXSS",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/RSNAKE.txt",
            "PAT/RSNAKE",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/URI-XSS.fuzzdb.txt",
            "SecLists/URI-XSS",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt",
            "SecLists/XSS-RSNAKE",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/human-friendly/XSS-Bypass-Strings.txt",
            "SecLists/XSS-Bypass",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/xss/xss-rsnake.txt",
            "fuzzdb/xss-rsnake",
        ),
    ),
    "sqli": (
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_Fuzz.txt",
            "PAT/SQLi-Generic_Fuzz",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_ErrorBased.txt",
            "PAT/SQLi-ErrorBased",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_UnionSelect.txt",
            "PAT/SQLi-UnionSelect",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_TimeBased.txt",
            "PAT/SQLi-TimeBased",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Auth_Bypass.txt",
            "PAT/SQLi-Auth_Bypass",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/MySQL.txt",
            "fuzzdb/MySQL",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/MSSQL.txt",
            "fuzzdb/MSSQL",
        ),
    ),
    "lfi": (
        PayloadSource(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
            "SecLists/LFI-Jhaddix",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt",
            "SecLists/LFI-LFISuite",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-linux-and-windows_by-1N3%40CrowdShield.txt",
            "SecLists/LFI-linux-windows",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/lfi/unix-sensible-file.txt",
            "fuzzdb/unix-sensible-file",
        ),
    ),
    "ssti": (
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/Intruder/SSJI.txt",
            "PAT/SSTI-SSJI",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/Intruder/CSTI.txt",
            "PAT/SSTI-CSTI",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/Intruder/Polyglot.txt",
            "PAT/SSTI-Polyglot",
        ),
    ),
    "cmdi": (
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/Command-Injection-Generic.txt",
            "PAT/CMDi-Generic",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt",
            "SecLists/commix",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/os-cmd-execution/unix-commix.txt",
            "fuzzdb/unix-commix",
        ),
    ),
    "redirect": (
        PayloadSource(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/open-redirects.txt",
            "SecLists/open-redirects",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Open%20Redirect/Intruders/openredirects.txt",
            "PAT/openredirects",
        ),
    ),
    "traversal": (
        PayloadSource(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
            "SecLists/traversal-Jhaddix",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/path-traversal/unix-path-traversal.txt",
            "fuzzdb/path-traversal-unix",
        ),
    ),
    "nosql": (
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/Intruder/NoSQL.txt",
            "PAT/NoSQL",
        ),
    ),
    "ssrf": (
        PayloadSource(
            "https://raw.githubusercontent.com/h0tak88r/Wordlists/master/vulns/ssrf.txt",
            "Wordlists/ssrf",
        ),
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/README.md",
            "PAT/SSRF-README",
            markdown=True,
        ),
    ),
    "xxe": (
        PayloadSource(
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/README.md",
            "PAT/XXE-README",
            markdown=True,
        ),
    ),
    "host_header": (),
}

LOCAL_SEED: dict[VulnType, tuple[str, ...]] = {
    "xss": ("{{MARKER}}", "'\"><{{MARKER}}"),
    "redirect": ("https://evil.example.test/redirect",),
    "nosql": ('{"$gt":""}', "' || '1'=='1", '{"$ne":null}'),
    "ssrf": ("http://127.0.0.1/", "http://169.254.169.254/"),
    "xxe": (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    ),
    "host_header": ("127.0.0.1", "localhost"),
}


def _fetch_url(url: str, timeout: float = 60.0) -> str | None:
    for attempt in range(3):
        try:
            r = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "VulnDix-PayloadUpdater/1.0"},
            )
            if r.status_code == 200:
                return r.text
            if r.status_code == 404:
                return None
        except requests.RequestException:
            pass
    return None


def _normalize_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith(("//", "/*", "* ", "- ", "| ", "##", "```")):
        return None
    if len(line) > MAX_LINE_LEN:
        return None
    if BLOCKED_PATTERNS.search(line):
        return None
    for prefix in ("payload:", "vector:", "test:"):
        if line.lower().startswith(prefix):
            line = line.split(":", 1)[1].strip()
    return line or None


def extract_from_markdown(text: str) -> list[str]:
    lines: list[str] = []
    for block in CODE_FENCE_RE.findall(text):
        lines.extend(parse_payload_lines(block))
    for m in INLINE_CODE_RE.findall(text):
        norm = _normalize_line(m)
        if norm and any(c in norm for c in ("'", '"', "<", "{", "$", ";", "../")):
            lines.append(norm)
    return lines


def parse_payload_lines(text: str, *, markdown: bool = False) -> list[str]:
    if markdown:
        return extract_from_markdown(text)
    out: list[str] = []
    for raw in text.splitlines():
        norm = _normalize_line(raw)
        if norm:
            out.append(norm)
    return out


def payload_dir_for(custom: Path | None) -> Path:
    return custom if custom else DEFAULT_PAYLOAD_DIR


def count_category_payloads(dest: Path, cat: VulnType) -> int:
    path = dest / f"{cat}.txt"
    if not path.is_file():
        return 0
    try:
        return len(parse_payload_lines(path.read_text(encoding="utf-8")))
    except OSError:
        return 0


def payload_sync_categories(categories: frozenset[VulnType]) -> frozenset[VulnType]:
    """Categorias do scan que usam arquivo .txt de fuzz (exclui passivas)."""
    return frozenset(
        c
        for c in categories
        if c in PAYLOAD_SOURCES and c not in PASSIVE_SCAN_CATEGORIES
    )


def min_payloads_for(cat: VulnType) -> int:
    if cat in SEED_ONLY_CATEGORIES:
        return max(1, len(LOCAL_SEED.get(cat, ())))
    if cat in SMALL_CATEGORIES:
        return MIN_PAYLOADS_READY_SMALL
    return MIN_PAYLOADS_READY


def categories_missing_payloads(
    dest: Path, categories: frozenset[VulnType]
) -> frozenset[VulnType]:
    missing: set[VulnType] = set()
    for cat in payload_sync_categories(categories):
        if count_category_payloads(dest, cat) < min_payloads_for(cat):
            missing.add(cat)
    return frozenset(missing)


def payloads_need_download(dest: Path, categories: frozenset[VulnType]) -> bool:
    return bool(categories_missing_payloads(dest, categories))


def _payloads_version_ok(dest: Path) -> bool:
    vf = dest / VERSION_FILE
    if not vf.is_file():
        return False
    try:
        return vf.read_text(encoding="utf-8").strip() == str(PAYLOADS_TOOL_VERSION)
    except OSError:
        return False


def ensure_payloads(
    dest_dir: Path | None,
    categories: frozenset[VulnType],
    *,
    max_per_category: int = 500,
    force: bool = False,
) -> bool:
    """
    Baixa payloads do GitHub para categorias que ainda não têm arquivo completo.
    Retorna True se executou download.
    """
    dest = payload_dir_for(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)

    sync_cats = payload_sync_categories(categories)
    missing = categories_missing_payloads(dest, categories)
    version_stale = not _payloads_version_ok(dest)

    if not force and not missing and not version_stale:
        return False

    to_fetch = sync_cats if force else (missing if missing else sync_cats)

    if force:
        eprint("[*] Atualização forçada de payloads (--refresh-payloads)...")
    elif missing:
        eprint(
            "[*] Payloads incompletos ou ausentes — baixando: "
            + ", ".join(sorted(missing))
        )
    elif version_stale:
        eprint("[*] Atualizando listas de payloads (versão do catálogo)...")
    else:
        eprint("[*] Baixando payloads do GitHub...")
    eprint("[*] (use --skip-payload-sync para desativar)")

    update_payloads(
        dest,
        to_fetch,
        max_per_category=max_per_category,
        keep_local=not force,
    )
    try:
        (dest / STAMP_FILE).write_text("ok\n", encoding="utf-8")
        (dest / VERSION_FILE).write_text(f"{PAYLOADS_TOOL_VERSION}\n", encoding="utf-8")
    except OSError:
        pass
    return True


def merge_unique(existing: Iterable[str], new_lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for line in list(existing) + list(new_lines):
        key = line.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(key)
    return merged


def update_payloads(
    dest_dir: Path | None = None,
    categories: frozenset[VulnType] | None = None,
    *,
    max_per_category: int = 500,
    keep_local: bool = True,
) -> dict[VulnType, int]:
    dest = dest_dir or DEFAULT_PAYLOAD_DIR
    dest.mkdir(parents=True, exist_ok=True)
    cats = categories or frozenset(PAYLOAD_SOURCES.keys())
    counts: dict[VulnType, int] = {}
    manifest_lines: list[str] = []

    eprint(f"[*] Atualizando payloads em {dest}")
    eprint("[*] Fontes: PayloadsAllTheThings + SecLists + fuzzdb (GitHub)")

    for cat in sorted(cats):
        sources = PAYLOAD_SOURCES.get(cat, ())
        collected: list[str] = []

        if keep_local:
            local_file = dest / f"{cat}.txt"
            if local_file.is_file():
                collected.extend(parse_payload_lines(local_file.read_text(encoding="utf-8")))

        collected.extend(LOCAL_SEED.get(cat, ()))

        ok_sources = 0
        for src in sources:
            eprint(f"[*] {cat}: baixando {src.label}...")
            text = _fetch_url(src.url)
            if not text:
                eprint(f"[-] {cat}: indisponível — {src.label}")
                continue
            lines = parse_payload_lines(text, markdown=src.markdown)
            collected = merge_unique(collected, lines)
            manifest_lines.append(f"{cat}\t{src.label}\t{src.url}\t{len(lines)}")
            ok_sources += 1
            eprint(f"[+] {cat}: +{len(lines)} de {src.label}")

        if ok_sources == 0:
            eprint(f"[-] {cat}: nenhuma fonte online; mantendo conteúdo local/seed.")

        collected = merge_unique([], collected)[:max_per_category]
        out_path = dest / f"{cat}.txt"
        header = (
            f"# VulnDix — {cat}.txt (gerado automaticamente)\n"
            f"# Total: {len(collected)} payloads | Fontes online: {ok_sources}\n"
            f"# Repositórios: swisskyrepo/PayloadsAllTheThings, danielmiessler/SecLists, fuzzdb-project/fuzzdb\n"
        )
        out_path.write_text(header + "\n".join(collected) + "\n", encoding="utf-8")
        counts[cat] = len(collected)
        eprint(f"[+] {cat}: {len(collected)} payloads → {out_path.name}")

    manifest_path = dest / MANIFEST_NAME
    merged_manifest = _merge_manifest(manifest_path, manifest_lines)
    manifest_path.write_text(merged_manifest, encoding="utf-8")
    eprint(f"[+] Manifesto: {manifest_path}")
    return counts


def _merge_manifest(manifest_path: Path, new_lines: list[str]) -> str:
    """Mantém entradas antigas de outras categorias ao atualizar só algumas."""
    header = "# categoria\tfonte\turl\tlinhas_extraidas\n"
    updated_cats = {line.split("\t", 1)[0] for line in new_lines if "\t" in line}
    kept: list[str] = []
    if manifest_path.is_file():
        for raw in manifest_path.read_text(encoding="utf-8").splitlines():
            if not raw.strip() or raw.startswith("#"):
                continue
            cat = raw.split("\t", 1)[0]
            if cat not in updated_cats:
                kept.append(raw)
    body = kept + new_lines
    return header + ("\n".join(body) + "\n" if body else "")


def main() -> int:
    import argparse

    p = argparse.ArgumentParser(description="Baixa payloads de repositórios públicos no GitHub.")
    p.add_argument("--dir", default=None, help="Diretório de destino (padrão: vulndix/payloads/)")
    p.add_argument("--categories", default=None, help="xss,sqli,... (padrão: todas)")
    p.add_argument("--max", type=int, default=500, help="Máximo de payloads por categoria.")
    p.add_argument("--no-keep-local", action="store_true", help="Não mesclar arquivo local existente.")
    args = p.parse_args()

    cats: frozenset[VulnType] | None = None
    if args.categories:
        parts = {x.strip().lower() for x in args.categories.split(",") if x.strip()}
        cats = frozenset(parts)  # type: ignore[arg-type]

    dest = Path(args.dir) if args.dir else None
    counts = update_payloads(
        dest,
        cats,
        max_per_category=args.max,
        keep_local=not args.no_keep_local,
    )
    total = sum(counts.values())
    eprint(f"\n[+] Concluído — {total} payloads em {len(counts)} categoria(s)")
    return 0 if total > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
