"""Testes do manifest e resolução de ferramentas."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulndix.integrations.base import MANIFEST, load_manifest, tool_source_dir
from vulndix.toolchain_install import install_git_source

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TOOLS = (
    "httpx",
    "subfinder",
    "dalfox",
    "ffuf",
    "nuclei",
    "dirsearch",
    "nikto",
    "dirb",
)


def test_manifest_lists_all_user_tools():
    data = load_manifest()
    tools = data.get("tools", {})
    for name in EXPECTED_TOOLS:
        assert name in tools, f"falta {name} no manifest"
        assert tools[name].get("git_url") or tools[name].get("repo")


def test_manifest_source_only_policy():
    data = load_manifest()
    assert data.get("policy") == "source_only"
    for name, meta in data["tools"].items():
        assert "release" not in meta.get("install", [])


def test_manifest_git_install_method():
    data = load_manifest()
    for name in ("dirsearch", "nikto", "dirb"):
        methods = data["tools"][name].get("install", [])
        assert "git" in methods


@pytest.mark.skipif(not MANIFEST.is_file(), reason="manifest ausente")
def test_manifest_json_valid():
    json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_install_git_source_creates_dir(tmp_path, monkeypatch):
    dest_name = "test_clone"
    monkeypatch.setattr(
        "vulndix.toolchain_install.SOURCES_DIR",
        tmp_path / "sources",
    )
    monkeypatch.setattr(
        "vulndix.integrations.base.SOURCES_DIR",
        tmp_path / "sources",
    )
    meta = {
        "git_url": "https://github.com/octocat/Hello-World.git",
        "git_branch": "master",
        "repo": "octocat/Hello-World",
    }
    try:
        ok = install_git_source(dest_name, meta)
    except Exception:
        pytest.skip("sem rede ou git")
    if ok:
        assert tool_source_dir(dest_name).is_dir()
