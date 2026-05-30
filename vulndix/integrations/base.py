"""Invoca ferramentas só a partir de código-fonte (Python/Perl/go run). Sem .exe vendored."""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulndix.models import Finding, ScanConfig
from vulndix.reporter import eprint

ROOT = Path(__file__).resolve().parents[2]
THIRD_PARTY = ROOT / "third_party"
SOURCES_DIR = THIRD_PARTY / "sources"
MANIFEST = THIRD_PARTY / "manifest.json"

# Fallback se go_run no manifest não existir no disco
GO_RUN_FALLBACKS: dict[str, list[str]] = {
    "httpx": ["./cmd/httpx", "."],
    "subfinder": ["./v2/cmd/subfinder", "./cmd/subfinder", "."],
    "dalfox": [".", "./cmd/dalfox"],
    "ffuf": ["."],
    "nuclei": ["./cmd/nuclei", "."],
}


@dataclass
class ToolInvocation:
    argv: list[str]
    cwd: Path | None = None
    tool: str = ""


@dataclass
class ToolResult:
    tool: str
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    raw_path: Path | None = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""


def tool_source_dir(name: str) -> Path:
    return SOURCES_DIR / name


def load_manifest() -> dict[str, Any]:
    if not MANIFEST.is_file():
        return {"tools": {}}
    return json.loads(MANIFEST.read_text(encoding="utf-8")) or {"tools": {}}


def _tool_meta(name: str) -> dict[str, Any]:
    return load_manifest().get("tools", {}).get(name, {})


def _which_go() -> str | None:
    """Go no PATH ou em locais padrão do Windows (após instalação recente)."""
    from shutil import which

    found = which("go")
    if found:
        return found
    if sys.platform.startswith("win"):
        for candidate in (
            Path(r"C:\Program Files\Go\bin\go.exe"),
            Path(r"C:\Go\bin\go.exe"),
            Path.home() / "go" / "bin" / "go.exe",
        ):
            if candidate.is_file():
                return str(candidate)
    return None


def _which(cmd: str) -> str | None:
    if cmd == "go":
        return _which_go()
    from shutil import which

    return which(cmd)


def _resolve_go(name: str, meta: dict, src: Path) -> ToolInvocation | None:
    go = _which("go")
    if not go:
        eprint(f"[-] {name}: Go não está no PATH — instale em https://go.dev/dl/")
        return None
    if not (src / "go.mod").is_file():
        eprint(f"[-] {name}: go.mod ausente em {src} — rode --install-tools")
        return None

    candidates: list[str] = []
    if meta.get("go_run"):
        candidates.append(meta["go_run"])
    candidates.extend(GO_RUN_FALLBACKS.get(name, ["."]))

    seen: set[str] = set()
    for pkg in candidates:
        if pkg in seen:
            continue
        seen.add(pkg)
        rel = pkg.removeprefix("./")
        check = src if pkg == "." else src / rel
        if pkg == "." or check.exists():
            return ToolInvocation(argv=[go, "run", pkg], cwd=src, tool=name)

    return ToolInvocation(argv=[go, "run", "."], cwd=src, tool=name)


def _resolve_dirb(meta: dict, src: Path) -> ToolInvocation | None:
    """Binário só se você compilou localmente (make); nunca .exe baixado."""
    rel = meta.get("build_binary", "dirb")
    built = src / rel
    if built.is_file() and not str(built).lower().endswith(".exe"):
        return ToolInvocation(argv=[str(built)], cwd=src, tool="dirb")
    if sys.platform.startswith("win"):
        eprint("[-] dirb: compile no WSL (make) ou use dirsearch no modo --deep")
        return None
    return None


def resolve_tool(name: str) -> ToolInvocation | None:
    meta = _tool_meta(name)
    src = tool_source_dir(name)
    runtime = meta.get("runtime")
    entry = meta.get("entry")

    if runtime == "python" and entry:
        script = src / entry
        if script.is_file():
            return ToolInvocation(
                argv=[sys.executable, str(script)],
                cwd=src,
                tool=name,
            )

    if runtime == "perl" and entry:
        script = src / entry
        perl = _which("perl")
        if script.is_file() and perl:
            return ToolInvocation(argv=[perl, str(script)], cwd=src, tool=name)
        if not perl:
            eprint(f"[-] {name}: Perl não encontrado no PATH")
        return None

    if runtime == "go" and src.is_dir():
        return _resolve_go(name, meta, src)

    if runtime == "native" and name == "dirb":
        return _resolve_dirb(meta, src)

    return None


def run_subprocess(
    cmd: list[str],
    *,
    timeout: int = 600,
    cwd: Path | None = None,
) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            errors="replace",
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except OSError as e:
        return -1, "", str(e)


def run_tool(name: str, config: ScanConfig, extra_args: list[str] | None = None) -> ToolResult:
    from vulndix.integrations import (
        dalfox,
        dirb,
        dirsearch,
        ffuf,
        httpx,
        nikto,
        nuclei,
        subfinder,
    )

    runners = {
        "httpx": httpx.run,
        "subfinder": subfinder.run,
        "dalfox": dalfox.run,
        "ffuf": ffuf.run,
        "nuclei": nuclei.run,
        "nikto": nikto.run,
        "dirsearch": dirsearch.run,
        "dirb": dirb.run,
    }
    fn = runners.get(name)
    if not fn:
        return ToolResult(tool=name, ok=False, error=f"ferramenta desconhecida: {name}")

    inv = resolve_tool(name)
    if not inv:
        eprint(
            f"[-] {name}: indisponível. Rode: python vulndix.py --install-tools "
            f"(fonte em {tool_source_dir(name)})"
        )
        return ToolResult(tool=name, ok=False, error="tool_not_found")

    try:
        return fn(inv, config, extra_args or [])
    except Exception as e:
        return ToolResult(tool=name, ok=False, error=str(e))


def parse_jsonl_findings(path: Path, default_type: str) -> list[Finding]:
    out: list[Finding] = []
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append(
            Finding(
                type=row.get("type", default_type),  # type: ignore[arg-type]
                endpoint=row.get("url", row.get("endpoint", "")),
                param=row.get("param", ""),
                location=row.get("location", "query"),  # type: ignore[arg-type]
                payload=row.get("payload", ""),
                confidence=row.get("confidence", "medium"),  # type: ignore[arg-type]
                evidence=row.get("evidence", row.get("matcher-name", str(row))[:500]),
            )
        )
    return out
