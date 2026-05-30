"""Adaptador nuclei + templates em third_party/data/nuclei-templates."""
from __future__ import annotations

import tempfile
from pathlib import Path

from vulndix.integrations._helpers import cmd_with
from vulndix.integrations.base import ROOT, ToolInvocation, ToolResult, parse_jsonl_findings, run_subprocess
from vulndix.models import ScanConfig

TEMPLATES_DIR = ROOT / "third_party" / "data" / "nuclei-templates"


def run(inv: ToolInvocation, config: ScanConfig, extra_args: list[str]) -> ToolResult:
    if not config.url:
        return ToolResult(tool="nuclei", ok=False, error="url_vazia")
    out_file = Path(tempfile.gettempdir()) / "vulndix_nuclei.jsonl"
    cmd = cmd_with(
        inv,
        "-u",
        config.url,
        "-silent",
        "-jsonl",
        "-o",
        str(out_file),
        "-severity",
        "critical,high",
        "-rate-limit",
        "15",
    )
    if TEMPLATES_DIR.is_dir():
        cmd.extend(["-templates", str(TEMPLATES_DIR)])
    if config.proxy:
        cmd.extend(["-proxy", config.proxy])
    cmd.extend(extra_args)
    code, stdout, stderr = run_subprocess(cmd, timeout=1800, cwd=inv.cwd)
    findings = parse_jsonl_findings(out_file, "info")
    return ToolResult(
        tool="nuclei",
        ok=code == 0 or bool(findings),
        findings=findings,
        raw_path=out_file if out_file.is_file() else None,
        stdout=stdout,
        stderr=stderr,
    )
