"""Adaptador dirsearch — repo maurosoria/dirsearch em sources/dirsearch."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from vulndix.integrations._helpers import cmd_with
from vulndix.integrations.base import ToolInvocation, ToolResult, run_subprocess
from vulndix.models import Finding, ScanConfig


def run(inv: ToolInvocation, config: ScanConfig, extra_args: list[str]) -> ToolResult:
    if not config.url:
        return ToolResult(tool="dirsearch", ok=False, error="url_vazia")
    parsed = urlparse(config.url)
    base = f"{parsed.scheme}://{parsed.netloc}/"
    out_dir = Path(tempfile.gettempdir()) / "vulndix_dirsearch"
    out_dir.mkdir(parents=True, exist_ok=True)
    report_json = out_dir / "report.json"
    cmd = cmd_with(
        inv,
        "-u",
        base,
        "--json-report",
        str(report_json),
        "-t",
        "8" if config.stealth_mode else "20",
        "--random-agent",
        "-q",
    )
    if config.proxy:
        cmd.extend(["--proxy", config.proxy])
    cmd.extend(extra_args)
    code, stdout, stderr = run_subprocess(cmd, timeout=2400, cwd=inv.cwd)
    findings: list[Finding] = []
    if report_json.is_file():
        try:
            data = json.loads(report_json.read_text(encoding="utf-8"))
            for row in data if isinstance(data, list) else []:
                findings.append(
                    Finding(
                        type="info",
                        endpoint=row.get("url", base),
                        param="path",
                        location="path",
                        payload=row.get("path", ""),
                        confidence="low",
                        evidence=f"dirsearch status={row.get('status')}",
                    )
                )
        except json.JSONDecodeError:
            pass
    return ToolResult(
        tool="dirsearch",
        ok=code == 0 or bool(findings),
        findings=findings[:100],
        raw_path=report_json if report_json.is_file() else None,
        stdout=stdout,
        stderr=stderr,
    )
