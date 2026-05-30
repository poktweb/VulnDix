"""Orquestração de fases por perfil stealth / deep."""
from __future__ import annotations

from vulndix.integrations.base import ToolResult, run_tool
from vulndix.models import Finding, ScanConfig
from vulndix.reporter import eprint


def run_stealth_recon(config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not config.use_toolchain:
        return findings
    for name in ("subfinder", "httpx"):
        eprint(f"[*] Toolchain (stealth): {name}...")
        res = run_tool(name, config)
        if res.findings:
            findings.extend(res.findings)
        if not res.ok and res.error:
            eprint(f"[-] {name}: {res.error}")
    return findings


def run_dalfox_phase(config: ScanConfig) -> list[Finding]:
    if not config.use_toolchain:
        return []
    eprint("[*] Toolchain: dalfox (XSS)...")
    res = run_tool("dalfox", config)
    if not res.ok and res.error:
        eprint(f"[-] dalfox: {res.error}")
    return res.findings


def run_deep_tools(config: ScanConfig) -> list[Finding]:
    if not config.deep_scan:
        return []
    findings: list[Finding] = []
    for name in ("ffuf", "dirsearch", "dirb", "nuclei", "nikto"):
        eprint(f"[*] Toolchain (deep): {name}...")
        res = run_tool(name, config)
        if res.findings:
            findings.extend(res.findings)
        if not res.ok and res.error:
            eprint(f"[-] {name}: {res.error}")
    return findings


def merge_findings(*groups: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Finding] = []
    for group in groups:
        for f in group:
            sig = (f.type, f.endpoint, f.param)
            if sig in seen:
                continue
            seen.add(sig)
            out.append(f)
    return out
