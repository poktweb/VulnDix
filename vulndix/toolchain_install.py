"""Clona código-fonte (GitHub/GitLab). Sem downloads de .exe ou releases pré-compilados."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from vulndix.integrations.base import (
    SOURCES_DIR,
    THIRD_PARTY,
    load_manifest,
    tool_source_dir,
)
from vulndix.reporter import eprint

try:
    import tarfile
except ImportError:
    tarfile = None  # type: ignore[assignment]

_UA = {"User-Agent": "VulnDix-installer/1.0"}


def purge_prebuilt_binaries() -> int:
    """Remove .exe e binários vendored em third_party (política source-only)."""
    removed = 0
    for sub in ("windows-amd64", "linux-amd64", "linux-arm64"):
        bin_dir = THIRD_PARTY / sub
        if not bin_dir.is_dir():
            continue
        for f in bin_dir.iterdir():
            if f.is_file() and f.name != ".gitkeep":
                try:
                    f.unlink()
                    removed += 1
                    eprint(f"[*] Removido: {f}")
                except OSError as e:
                    eprint(f"[-] Não foi possível remover {f}: {e}")
    if removed:
        eprint(f"[+] {removed} binário(s) pré-compilado(s) removido(s).")
    else:
        eprint("[*] Nenhum binário pré-compilado em third_party/.")
    return removed


def _download(url: str, dest: Path) -> bool:
    eprint(f"[*] Baixando {url[:95]}...")
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = resp.read()
        if len(data) < 256 or b"<html" in data[:500].lower():
            eprint("[-] Download inválido (HTML ou vazio)")
            return False
        dest.write_bytes(data)
        return True
    except Exception as e:
        eprint(f"[-] Falha no download: {e}")
        return False


def _extract_archive(archive: Path, dest_dir: Path) -> bool:
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        if zipfile.is_zipfile(archive):
            shutil.unpack_archive(str(archive), str(dest_dir), "zip")
            return True
        if archive.name.endswith(".tar.gz"):
            shutil.unpack_archive(str(archive), str(dest_dir), "gztar")
            return True
    except Exception as e:
        eprint(f"[-] Extração falhou: {e}")
    return False


def _run_git(args: list[str], cwd: Path | None = None) -> bool:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=600,
            errors="replace",
        )
        if proc.returncode != 0:
            eprint(f"[-] git: {proc.stderr.strip()[:220]}")
            return False
        return True
    except FileNotFoundError:
        return False
    except subprocess.TimeoutExpired:
        eprint("[-] git: timeout")
        return False


def _archive_zip_url(git_url: str, ref: str) -> str | None:
    ref = ref or "main"
    if "github.com" in git_url:
        parts = git_url.rstrip("/").replace(".git", "").split("github.com/")[-1].split("/")
        if len(parts) < 2:
            return None
        owner, repo = parts[0], parts[1]
        if ref.startswith("v") and ref[1:2].isdigit():
            return f"https://github.com/{owner}/{repo}/archive/refs/tags/{ref}.zip"
        return f"https://github.com/{owner}/{repo}/archive/refs/heads/{ref}.zip"
    if "gitlab.com" in git_url:
        path = git_url.rstrip("/").replace(".git", "").split("gitlab.com/")[-1]
        project = path.split("/")[-1]
        ref_slug = ref.replace("/", "-")
        return f"https://gitlab.com/{path}/-/archive/{ref}/{project}-{ref_slug}.zip"
    return None


def _clone_via_zip(git_url: str, dest: Path, ref: str | None) -> bool:
    url = _archive_zip_url(git_url, ref or "main")
    if not url:
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        zpath = Path(tmp) / "repo.zip"
        if not _download(url, zpath):
            return False
        extract_to = Path(tmp) / "out"
        if not _extract_archive(zpath, extract_to):
            return False
        subs = [p for p in extract_to.iterdir() if p.is_dir()]
        if not subs:
            return False
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(subs[0], dest)
    eprint(f"[+] Clone ZIP -> {dest}")
    return dest.is_dir()


def install_git_source(name: str, meta: dict) -> bool:
    git_url = meta.get("git_url") or f"https://github.com/{meta.get('repo', '')}.git"
    if "://" not in git_url:
        return False

    dest = tool_source_dir(name)
    if dest.is_dir() and any(dest.iterdir()):
        eprint(f"[+] {name}: código já em {dest}")
        return True

    tag = meta.get("git_tag")
    branch = meta.get("git_branch") or "main"
    ref = tag or branch

    if _run_git(["--version"]):
        dest.parent.mkdir(parents=True, exist_ok=True)
        clone_args = ["clone", "--depth", "1", "--single-branch"]
        if tag:
            clone_args.extend(["--branch", tag])
        elif branch:
            clone_args.extend(["--branch", branch])
        clone_args.extend([git_url, str(dest)])
        if _run_git(clone_args):
            eprint(f"[+] {name}: git clone -> {dest}")
            return True
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)

    eprint(f"[*] {name}: tentando ZIP do repositório ({ref})...")
    return _clone_via_zip(git_url, dest, ref)


def install_pip_deps(name: str, meta: dict) -> bool:
    src = tool_source_dir(name)
    req = meta.get("pip_requirements")
    if not req:
        return True
    req_path = src / req
    if not req_path.is_file():
        eprint(f"[-] {name}: {req} não encontrado")
        return False
    eprint(f"[*] {name}: pip install -r {req}...")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q", "-r", str(req_path)],
            capture_output=True,
            text=True,
            timeout=600,
            errors="replace",
        )
        if proc.returncode != 0:
            eprint(f"[-] pip: {proc.stderr[:300]}")
            return False
        eprint(f"[+] {name}: dependências Python OK")
        return True
    except Exception as e:
        eprint(f"[-] pip: {e}")
        return False


def install_make_build(name: str, meta: dict) -> bool:
    """Compila dirb a partir do fonte (Linux/WSL). Não instala .exe de terceiros."""
    if sys.platform.startswith("win"):
        eprint(f"[*] {name}: no Windows compile no WSL com 'make' dentro de sources/dirb")
        return False

    src = tool_source_dir(name)
    if not src.is_dir():
        return False
    cwd = src if (src / "Makefile").is_file() else src
    if not (cwd / "Makefile").is_file():
        eprint(f"[-] {name}: Makefile não encontrado")
        return False
    eprint(f"[*] {name}: make em {cwd}...")
    try:
        proc = subprocess.run(
            ["make"],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=300,
            errors="replace",
        )
        if proc.returncode != 0:
            eprint(f"[-] make: {proc.stderr[:300]}")
            return False
    except FileNotFoundError:
        eprint(f"[-] {name}: instale build-essential (make, gcc)")
        return False

    rel = meta.get("build_binary", "dirb")
    built = src / rel
    if not built.is_file():
        eprint(f"[-] {name}: binário local não gerado em {built}")
        return False
    eprint(f"[+] {name}: compilado em {built} (só no seu ambiente, não copiado para third_party)")
    return True


def install_extra_repos(meta: dict) -> bool:
    ok = True
    for extra in meta.get("extra_repos", []):
        dest_rel = extra.get("dest", extra.get("name", ""))
        dest = THIRD_PARTY / dest_rel
        name = extra.get("name", dest_rel.split("/")[-1])
        if dest.is_dir() and any(dest.iterdir()):
            eprint(f"[+] {name}: já em {dest}")
            continue
        fake_meta = {
            "git_url": extra["git_url"],
            "git_branch": extra.get("git_branch", "main"),
            "repo": extra["git_url"].split("github.com/")[-1].replace(".git", ""),
        }
        staging = SOURCES_DIR / f"_staging_{name}"
        if staging.is_dir():
            shutil.rmtree(staging, ignore_errors=True)
        if install_git_source(f"_staging_{name}", fake_meta) and staging.is_dir():
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                shutil.rmtree(dest, ignore_errors=True)
            shutil.move(str(staging), str(dest))
            eprint(f"[+] {name}: -> {dest}")
        else:
            ok = False
    return ok


def install_tool(name: str, meta: dict) -> bool:
    methods = meta.get("install", ["git"])
    if isinstance(methods, str):
        methods = [methods]

    ok_any = False
    if "git" in methods and install_git_source(name, meta):
        ok_any = True
    if "pip" in methods and install_pip_deps(name, meta):
        ok_any = True
    if "build_make" in methods and install_make_build(name, meta):
        ok_any = True
    if meta.get("extra_repos"):
        install_extra_repos(meta)
    if meta.get("note") and meta.get("runtime") == "go":
        eprint(f"[*] {name}: execute com Go instalado (go run no código clonado)")
    elif meta.get("note"):
        eprint(f"[*] {name}: {meta['note']}")

    if "git" in methods and tool_source_dir(name).is_dir() and any(tool_source_dir(name).iterdir()):
        ok_any = True
    return ok_any


def install_all_tools() -> int:
    manifest = load_manifest()
    if manifest.get("policy") == "source_only":
        eprint("[*] Política: somente código-fonte (sem .exe de releases).")
        purge_prebuilt_binaries()

    tools = manifest.get("tools", {})
    if not tools:
        eprint("[-] manifest.json vazio.")
        return 1

    SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    eprint(f"[*] Código-fonte: {SOURCES_DIR}")

    ok = 0
    for name, meta in tools.items():
        eprint(f"\n[*] === {name} ===")
        if install_tool(name, meta):
            ok += 1
        else:
            eprint(f"[-] {name}: instalação incompleta")

    eprint(f"\n[*] Ferramentas Go exigem: https://go.dev/dl/ (go run compila na sua máquina)")
    eprint(f"[*] Concluído: {ok}/{len(tools)}")
    return 0 if ok > 0 else 1
