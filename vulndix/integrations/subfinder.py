"""Adaptador subfinder — fontes passivas em modo stealth."""
from __future__ import annotations

import tempfile
from pathlib import Path
from urllib.parse import urlparse

from vulndix.integrations._helpers import cmd_with
from vulndix.integrations.base import ToolInvocation, ToolResult, run_subprocess
from vulndix.models import ScanConfig


def run(inv: ToolInvocation, config: ScanConfig, extra_args: list[str]) -> ToolResult:
    parsed = urlparse(config.url)
    domain = parsed.hostname or ""
    if not domain:
        return ToolResult(tool="subfinder", ok=False, error="dominio_invalido")
    root = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain
    out_file = Path(tempfile.gettempdir()) / f"vulndix_subfinder_{root}.txt"
    passive_sources = "crtsh,waybackarchive,hackertarget,urlscan"
    cmd = cmd_with(
        inv,
        "-d",
        root,
        "-silent",
        "-o",
        str(out_file),
        "-sources",
        passive_sources,
    )
    if config.stealth_mode:
        cmd.extend(["-t", "3"])
    cmd.extend(extra_args)
    code, stdout, stderr = run_subprocess(cmd, timeout=600, cwd=inv.cwd)
    subs: list[str] = []
    if out_file.is_file():
        subs = [ln.strip() for ln in out_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return ToolResult(
        tool="subfinder",
        ok=code == 0,
        raw_path=out_file if out_file.is_file() else None,
        stdout="\n".join(subs[:50]),
        stderr=stderr,
    )
