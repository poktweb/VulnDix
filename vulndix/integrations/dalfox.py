"""Adaptador dalfox — XSS via go run em sources/dalfox."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from vulndix.integrations._helpers import cmd_with
from vulndix.integrations.base import ToolInvocation, ToolResult, run_subprocess
from vulndix.models import Finding, ScanConfig


def run(inv: ToolInvocation, config: ScanConfig, extra_args: list[str]) -> ToolResult:
    if not config.url:
        return ToolResult(tool="dalfox", ok=False, error="url_vazia")
    out_file = Path(tempfile.gettempdir()) / "vulndix_dalfox_out.json"
    # go run: inv.argv = [go, run, .] — subcomando url vem depois do pacote
    if inv.argv[:2] == ["go", "run"]:
        cmd = inv.argv + ["url", config.url, "--silence", "--format", "json", "-o", str(out_file)]
    else:
        cmd = cmd_with(
            inv,
            "url",
            config.url,
            "--silence",
            "--format",
            "json",
            "-o",
            str(out_file),
        )
    if config.stealth_mode:
        cmd.extend(["--mining-only"])
    else:
        cmd.extend(["--worker", "5"])
    if config.proxy:
        cmd.extend(["--proxy", config.proxy])
    cmd.extend(extra_args)
    code, stdout, stderr = run_subprocess(cmd, timeout=900, cwd=inv.cwd)
    findings: list[Finding] = []
    if out_file.is_file():
        raw = out_file.read_text(encoding="utf-8", errors="replace").strip()
        if raw.startswith("["):
            try:
                rows = json.loads(raw)
            except json.JSONDecodeError:
                rows = []
            for row in rows if isinstance(rows, list) else []:
                findings.append(
                    Finding(
                        type="xss",
                        endpoint=row.get("data", config.url),
                        param=row.get("param", ""),
                        location="query",
                        payload=row.get("payload", ""),
                        confidence="high",
                        evidence=str(row.get("evidence", "dalfox"))[:500],
                    )
                )
        else:
            for line in raw.splitlines():
                if line.strip():
                    findings.append(
                        Finding(
                            type="xss",
                            endpoint=config.url,
                            param="",
                            location="query",
                            payload="",
                            confidence="medium",
                            evidence=f"dalfox: {line[:400]}",
                        )
                    )
    return ToolResult(
        tool="dalfox",
        ok=code == 0 or bool(findings),
        findings=findings,
        raw_path=out_file if out_file.is_file() else None,
        stdout=stdout,
        stderr=stderr,
    )
