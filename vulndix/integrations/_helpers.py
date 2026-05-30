"""Helpers para montar comando a partir de ToolInvocation."""
from __future__ import annotations

from vulndix.integrations.base import ToolInvocation


def cmd_with(inv: ToolInvocation, *parts: str) -> list[str]:
    return list(inv.argv) + list(parts)
