"""Adaptador ffuf."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from vulndix.integrations._helpers import cmd_with
from vulndix.integrations.base import ToolInvocation, ToolResult, run_subprocess
from vulndix.models import Finding, ScanConfig
from vulndix.payload_updater import DEFAULT_PAYLOAD_DIR


def run(inv: ToolInvocation, config: ScanConfig, extra_args: list[str]) -> ToolResult:
    wl = DEFAULT_PAYLOAD_DIR / "wordlists" / "common-dirs.txt"
    if not wl.is_file():
        return ToolResult(tool="ffuf", ok=False, error="wordlist_ausente")
    parsed = urlparse(config.url)
    base = f"{parsed.scheme}://{parsed.netloc}/FUZZ"
    out_file = Path(tempfile.gettempdir()) / "vulndix_ffuf.json"
    cmd = cmd_with(
        inv,
        "-u",
        base,
        "-w",
        str(wl),
        "-of",
        "json",
        "-o",
        str(out_file),
        "-t",
        "5",
        "-rate",
        "10",
        "-s",
    )
    if config.proxy:
        cmd.extend(["-x", config.proxy])
    cmd.extend(extra_args)
    code, stdout, stderr = run_subprocess(cmd, timeout=1200, cwd=inv.cwd)
    findings: list[Finding] = []
    if out_file.is_file():
        try:
            data = json.loads(out_file.read_text(encoding="utf-8"))
            for r in data.get("results", []):
                findings.append(
                    Finding(
                        type="info",
                        endpoint=r.get("url", base),
                        param="FUZZ",
                        location="path",
                        payload=r.get("input", {}).get("FUZZ", ""),
                        confidence="low",
                        evidence=f"ffuf status={r.get('status')}",
                    )
                )
        except json.JSONDecodeError:
            pass
    return ToolResult(tool="ffuf", ok=code == 0, findings=findings, raw_path=out_file, stdout=stdout, stderr=stderr)
