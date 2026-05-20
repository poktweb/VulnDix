"""Fuzz de diretórios e subdomínios com wordlist (estilo ffuf: FUZZ na URL)."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse, urlunparse

import requests

from vulndix.models import Finding, ScanConfig
from vulndix.reporter import eprint, write_report
from vulndix.transport import build_session, normalize_request_url

FUZZ_TOKEN = "FUZZ"
DEFAULT_MATCH_CODES = frozenset({200, 201, 204, 301, 302, 307, 308, 401, 403, 405})
DEFAULT_WORDLIST_DIR = Path(__file__).resolve().parent / "payloads" / "wordlists"
BUILTIN_WORDLISTS = {
    "common-dirs": "common-dirs.txt",
    "common-subdomains": "subdomains-top.txt",
}

FuzzMode = Literal["directory", "subdomain"]


@dataclass(frozen=True)
class FuzzTarget:
    mode: FuzzMode
    template: str
    base_domain: str = ""


@dataclass
class WordlistHit:
    word: str
    url: str
    status: int
    size: int
    elapsed_ms: float
    mode: FuzzMode

    def to_finding(self) -> Finding:
        label = "subdomínio" if self.mode == "subdomain" else "diretório"
        return Finding(
            type="info",
            endpoint=self.url,
            param=self.word,
            location="path",
            payload=self.word,
            confidence="medium",
            evidence=f"{label} — HTTP {self.status}, {self.size} bytes, {self.elapsed_ms:.0f} ms",
        )


def resolve_wordlist_path(raw: str) -> Path:
    key = raw.strip().lower()
    if key in BUILTIN_WORDLISTS:
        return DEFAULT_WORDLIST_DIR / BUILTIN_WORDLISTS[key]
    path = Path(raw)
    if not path.is_file():
        raise FileNotFoundError(
            f"Wordlist não encontrada: {raw!r}. "
            f"Atalhos: {', '.join(BUILTIN_WORDLISTS)} (em {DEFAULT_WORDLIST_DIR})"
        )
    return path


def load_wordlist(path: Path, *, max_lines: int = 0) -> list[str]:
    words: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            words.append(line)
        if max_lines and len(words) >= max_lines:
            break
    return words


def _has_fuzz_token(text: str) -> bool:
    return FUZZ_TOKEN in text.upper()


def _replace_fuzz(text: str, word: str, *, upper: bool = False) -> str:
    token = FUZZ_TOKEN if not upper else FUZZ_TOKEN.upper()
    if upper and token not in text:
        # template may use lowercase FUZZ only
        return text.replace(FUZZ_TOKEN, word).replace("fuzz", word)
    return text.replace(token, word).replace("fuzz", word)


def parse_fuzz_target(url: str) -> FuzzTarget:
    """Interpreta -u com FUZZ (path) ou FUZZ.dominio / host FUZZ."""
    raw = url.strip()
    if not _has_fuzz_token(raw):
        raise ValueError(
            f"A URL deve conter o marcador {FUZZ_TOKEN} "
            f"(ex.: https://alvo.com/{FUZZ_TOKEN} ou https://{FUZZ_TOKEN}.alvo.com)"
        )

    # FUZZ.url → trata .url como sufixo do domínio base (ex. FUZZ.example.com)
    if raw.lower().startswith("fuzz."):
        base = raw.split(".", 1)[1]
        template = f"https://{FUZZ_TOKEN}.{base}/"
        return FuzzTarget("subdomain", template, base_domain=base)

    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)
    host = parsed.hostname or ""
    host_upper = host.upper()

    if FUZZ_TOKEN in host_upper:
        # subdomínio: FUZZ está no hostname
        parts = host.split(".")
        fuzz_idx = next(
            (i for i, p in enumerate(parts) if p.upper() == FUZZ_TOKEN),
            -1,
        )
        if fuzz_idx < 0:
            raise ValueError("Marcador FUZZ inválido no hostname.")
        base_domain = ".".join(parts[fuzz_idx + 1 :])
        if not base_domain:
            raise ValueError(
                "Domínio base ausente após FUZZ (use https://FUZZ.exemplo.com)."
            )
        template = urlunparse(
            (parsed.scheme or "https", host, parsed.path or "/", parsed.params, parsed.query, "")
        )
        return FuzzTarget("subdomain", template, base_domain=base_domain)

    if _has_fuzz_token(raw):
        return FuzzTarget("directory", raw)

    raise ValueError("Não foi possível determinar o modo de fuzz para esta URL.")


def _join_dir_url(base: str, word: str) -> str:
    """Substitui FUZZ no path ou acrescenta segmento após barra final."""
    if FUZZ_TOKEN not in base.upper() and "fuzz" not in base.lower():
        return base
    parsed = urlparse(base)
    path = parsed.path or "/"
    if FUZZ_TOKEN in path.upper() or "fuzz" in path.lower():
        path = _replace_fuzz(path, word)
    elif path.endswith("/"):
        path = path + word.lstrip("/")
    else:
        path = f"{path}/{word.lstrip('/')}"
    while "//" in path.replace("://", ""):
        path = path.replace("//", "/")
    return urlunparse(
        (parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment)
    )


def build_fuzz_url(target: FuzzTarget, word: str) -> str:
    word = word.strip().lstrip("/")
    if not word:
        raise ValueError("Entrada vazia na wordlist.")

    if target.mode == "subdomain":
        host = urlparse(target.template).hostname or ""
        new_host = _replace_fuzz(host, word, upper=True)
        parsed = urlparse(target.template)
        netloc = new_host
        if parsed.port:
            netloc = f"{new_host}:{parsed.port}"
        url = urlunparse(
            (
                parsed.scheme or "https",
                netloc,
                parsed.path or "/",
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        return normalize_request_url(url)

    if FUZZ_TOKEN in target.template.upper() or "fuzz" in target.template.lower():
        url = _join_dir_url(target.template, word)
        return normalize_request_url(url)

    return normalize_request_url(target.template)


@dataclass
class _Baseline:
    status: int
    size: int
    samples: int = 1


def _probe(
    session: requests.Session,
    url: str,
    method: str,
    timeout: float,
) -> tuple[int, int, float]:
    t0 = time.perf_counter()
    if method.upper() == "HEAD":
        r = session.head(url, allow_redirects=False, timeout=timeout)
        body_len = int(r.headers.get("Content-Length", 0) or 0)
    else:
        r = session.get(url, allow_redirects=False, timeout=timeout)
        body_len = len(r.content)
    elapsed = (time.perf_counter() - t0) * 1000.0
    return r.status_code, body_len, elapsed


def _is_interesting(
    status: int,
    size: int,
    *,
    match_codes: frozenset[int],
    baseline: _Baseline | None,
    hide_baseline: bool,
) -> bool:
    if status not in match_codes:
        return False
    if not hide_baseline or baseline is None:
        return True
    if status != baseline.status:
        return True
    diff = abs(size - baseline.size)
    return diff > max(32, int(baseline.size * 0.05))


def run_wordlist_fuzz(
    config: ScanConfig,
    target: FuzzTarget,
    words: list[str],
    *,
    output_path: Path | None = None,
    jsonl: bool = False,
) -> list[WordlistHit]:
    if not words:
        eprint("[-] Wordlist vazia.")
        return []

    session = build_session(config, pool_size=config.threads * 2)
    method = (config.wordlist_method or "GET").upper()
    timeout = config.probe_timeout_s
    match_codes = config.fuzz_match_codes or DEFAULT_MATCH_CODES
    hide_baseline = config.fuzz_filter_baseline

    baseline: _Baseline | None = None
    if hide_baseline:
        junk = f"vulndix-{uuid.uuid4().hex[:12]}"
        try:
            junk_url = build_fuzz_url(target, junk)
            st, sz, _ = _probe(session, junk_url, method, timeout)
            baseline = _Baseline(st, sz)
            eprint(f"[*] Baseline (ruído): HTTP {st}, {sz} bytes — respostas iguais serão ocultadas")
        except requests.RequestException as e:
            eprint(f"[*] Baseline não medida ({e}); exibindo todos os códigos filtrados.")

    hits: list[WordlistHit] = []
    total = len(words)
    t0 = time.perf_counter()
    done = 0
    per_delay = config.delay_ms / 1000.0 / max(1, config.threads)

    eprint(
        f"[*] Fuzz {target.mode}: {total} palavras | "
        f"threads={config.threads} | método={method} | códigos={sorted(match_codes)}"
    )

    def work(word: str) -> WordlistHit | None:
        if per_delay > 0:
            time.sleep(per_delay)
        try:
            url = build_fuzz_url(target, word)
            status, size, elapsed = _probe(session, url, method, timeout)
        except requests.RequestException:
            return None
        if not _is_interesting(
            status, size, match_codes=match_codes, baseline=baseline, hide_baseline=hide_baseline
        ):
            return None
        hit = WordlistHit(word=word, url=url, status=status, size=size, elapsed_ms=elapsed, mode=target.mode)
        eprint(f"[+] [{status}] {size:6d}b  {word}  →  {url}")
        return hit

    max_inflight = max(32, config.threads * 6)
    with ThreadPoolExecutor(max_workers=max(1, config.threads)) as ex:
        pending: set = set()
        it = iter(words)

        def fill() -> None:
            nonlocal pending
            while len(pending) < max_inflight:
                try:
                    w = next(it)
                except StopIteration:
                    break
                pending.add(ex.submit(work, w))

        fill()
        while pending:
            done_set, pending = wait(pending, return_when=FIRST_COMPLETED)
            for fut in done_set:
                try:
                    h = fut.result()
                    if h:
                        hits.append(h)
                except Exception as e:
                    eprint(f"[-] Erro: {e}")
                done += 1
            fill()
            if done == total or (done > 0 and done % max(50, total // 20) == 0):
                elapsed = time.perf_counter() - t0
                rate = done / elapsed if elapsed > 0 else 0
                eprint(f"[*] Progresso: {done}/{total} ({100 * done / total:.1f}%) — {rate:.1f} req/s")

    elapsed = time.perf_counter() - t0
    eprint(f"\n[+] Fuzz concluído: {len(hits)} hit(s) em {total} requisições ({elapsed:.1f}s)")

    findings = [h.to_finding() for h in hits]
    if findings and output_path:
        write_report(
            findings,
            output_path,
            config,
            meta={
                "fuzz_mode": target.mode,
                "wordlist_entries": total,
                "hits": len(hits),
            },
        )
        eprint(f"[+] Relatório: {output_path}")
    if jsonl:
        import json
        import sys

        for h in hits:
            print(
                json.dumps(
                    {
                        "word": h.word,
                        "url": h.url,
                        "status": h.status,
                        "size": h.size,
                        "mode": h.mode,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )

    return hits
