"""Adaptador httpx (ProjectDiscovery)."""
from __future__ import annotations

import tempfile
from pathlib import Path
from urllib.parse import urlparse

from vulndix.integrations._helpers import cmd_with
from vulndix.integrations.base import ToolInvocation, ToolResult, run_subprocess
from vulndix.models import Finding, ScanConfig


def run(inv: ToolInvocation, config: ScanConfig, extra_args: list[str]) -> ToolResult:
    host = urlparse(config.url).netloc
    if not host:
        return ToolResult(tool="httpx", ok=False, error="url_invalida")
    target_file = Path(tempfile.gettempdir()) / f"vulndix_httpx_{host.replace(':', '_')}.txt"
    target_file.write_text(host + "\n", encoding="utf-8")
    out_file = target_file.with_suffix(".out.jsonl")
    threads = "3" if config.stealth_mode else "10"
    cmd = cmd_with(
        inv,
        "-l",
        str(target_file),
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-json",
        "-o",
        str(out_file),
        "-threads",
        threads,
    )
    if config.proxy:
        cmd.extend(["-proxy", config.proxy])
    cmd.extend(extra_args)
    code, stdout, stderr = run_subprocess(cmd, timeout=300, cwd=inv.cwd)
    findings: list[Finding] = []
    if out_file.is_file():
        for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            findings.append(
                Finding(
                    type="info",
                    endpoint=line[:200],
                    param="",
                    location="query",
                    payload="",
                    confidence="low",
                    evidence=f"httpx: {line[:400]}",
                )
            )
    return ToolResult(
        tool="httpx",
        ok=code == 0,
        findings=findings,
        raw_path=out_file if out_file.is_file() else None,
        stdout=stdout,
        stderr=stderr,
    )
