from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulndix.models import Finding, ScanConfig


def eprint(*args, **kwargs) -> None:
    kwargs.setdefault("flush", True)
    print(*args, file=sys.stderr, **kwargs)


def print_summary(
    findings: list[Finding],
    config: ScanConfig,
    *,
    pages_crawled: int = 0,
    points_tested: int = 0,
    probes_run: int = 0,
) -> None:
    sep = "═" * 62
    eprint(f"\n{sep}")
    eprint("  VulnDix — Resumo da varredura")
    eprint(f"  Alvo: {config.url}")
    eprint(f"  Data: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    if pages_crawled:
        eprint(f"  Páginas: {pages_crawled} | Pontos testados: {points_tested} | Probes: {probes_run}")
    eprint(sep)

    if not findings:
        eprint("")
        eprint("  ┌────────────────────────────────────────────────────────────┐")
        eprint("  │  NENHUMA VULNERABILIDADE ENCONTRADA                       │")
        eprint("  │  Nada foi reportado nesta varredura.                      │")
        eprint("  └────────────────────────────────────────────────────────────┘")
        eprint("")
        eprint("  (Modo estrito: só achados confirmados; reflexões inofensivas ignoradas.)")
        eprint(sep + "\n")
        return

    by_type = Counter(f.type for f in findings)
    eprint(f"\n  Total: {len(findings)} achado(s) confirmado(s)")
    for t, n in sorted(by_type.items()):
        eprint(f"    • {t}: {n}")

    eprint(f"\n{'─' * 62}")
    for i, f in enumerate(findings, 1):
        eprint(f"\n  [{i}] {f.type.upper()} — confiança {f.confidence}")
        eprint(f"      Parâmetro : {f.param} ({f.location})")
        eprint(f"      Endpoint  : {f.endpoint[:110]}{'…' if len(f.endpoint) > 110 else ''}")
        eprint(f"      Payload   : {f.payload[:100]}{'…' if len(f.payload) > 100 else ''}")
        eprint(f"      Evidência : {f.evidence}")
    eprint(f"\n{sep}\n")


def emit_jsonl(findings: list[Finding]) -> None:
    for f in findings:
        print(json.dumps(f.to_dict(), ensure_ascii=False), flush=True)


def write_report(
    findings: list[Finding],
    path: Path,
    config: ScanConfig,
    *,
    meta: dict[str, Any] | None = None,
) -> None:
    meta = meta or {}
    payload: dict[str, Any] = {
        "tool": "VulnDix",
        "target": config.url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "categories": sorted(config.categories),
        "strict_mode": True,
        "summary": {
            "total": len(findings),
            "by_type": dict(Counter(f.type for f in findings)),
            "by_confidence": dict(Counter(f.confidence for f in findings)),
        },
        "scan": meta,
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
