"""Adaptador dirb — repo v0re/dirb (make) ou binário vendored."""
from __future__ import annotations

import tempfile
from pathlib import Path
from urllib.parse import urlparse

from vulndix.integrations._helpers import cmd_with
from vulndix.integrations.base import ToolInvocation, ToolResult, tool_source_dir, run_subprocess
from vulndix.models import Finding, ScanConfig


def _default_wordlist() -> Path | None:
    src = tool_source_dir("dirb")
    for candidate in (
        src / "wordlists" / "common.txt",
        src / "wordlists" / "big.txt",
        src / "dirb" / "wordlists" / "common.txt",
        src / "sources" / "wordlists" / "common.txt",
    ):
        if candidate.is_file():
            return candidate
    return None


def run(inv: ToolInvocation, config: ScanConfig, extra_args: list[str]) -> ToolResult:
    if not config.url:
        return ToolResult(tool="dirb", ok=False, error="url_vazia")
    wl = _default_wordlist()
    if not wl:
        return ToolResult(tool="dirb", ok=False, error="wordlist_dirb_ausente")
    out_file = Path(tempfile.gettempdir()) / "vulndix_dirb.txt"
    cmd = cmd_with(inv, config.url, str(wl), "-o", str(out_file), "-S")
    cmd.extend(extra_args)
    code, stdout, stderr = run_subprocess(cmd, timeout=2400, cwd=inv.cwd)
    findings: list[Finding] = []
    if out_file.is_file():
        for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().startswith("+"):
                findings.append(
                    Finding(
                        type="info",
                        endpoint=config.url,
                        param="path",
                        location="path",
                        payload="",
                        confidence="low",
                        evidence=f"dirb: {line.strip()[:300]}",
                    )
                )
    return ToolResult(
        tool="dirb",
        ok=code == 0 or bool(findings),
        findings=findings[:80],
        raw_path=out_file if out_file.is_file() else None,
        stdout=stdout,
        stderr=stderr,
    )
