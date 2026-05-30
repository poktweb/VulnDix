"""Adaptador nikto — código Perl clonado em sources/nikto."""
from __future__ import annotations

import tempfile
from pathlib import Path

from vulndix.integrations._helpers import cmd_with
from vulndix.integrations.base import ToolInvocation, ToolResult, run_subprocess
from vulndix.models import Finding, ScanConfig


def run(inv: ToolInvocation, config: ScanConfig, extra_args: list[str]) -> ToolResult:
    if not config.url:
        return ToolResult(tool="nikto", ok=False, error="url_vazia")
    out_file = Path(tempfile.gettempdir()) / "vulndix_nikto.txt"
    cmd = cmd_with(inv, "-h", config.url, "-output", str(out_file), "-Format", "txt")
    cmd.extend(extra_args)
    code, stdout, stderr = run_subprocess(cmd, timeout=2400, cwd=inv.cwd)
    findings: list[Finding] = []
    if out_file.is_file():
        for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("+") and ("OSVDB" in line or "CVE" in line):
                findings.append(
                    Finding(
                        type="info",
                        endpoint=config.url,
                        param="",
                        location="query",
                        payload="",
                        confidence="medium",
                        evidence=f"nikto: {line.strip()[:400]}",
                    )
                )
    return ToolResult(
        tool="nikto",
        ok=code == 0,
        findings=findings[:30],
        raw_path=out_file if out_file.is_file() else None,
        stdout=stdout,
        stderr=stderr,
    )
