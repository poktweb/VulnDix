"""Adaptadores — execução só a partir de código-fonte clonado."""
from vulndix.integrations.base import ToolResult, resolve_tool, run_tool
from vulndix.integrations.registry import run_deep_tools, run_stealth_recon

__all__ = [
    "ToolResult",
    "resolve_tool",
    "run_tool",
    "run_stealth_recon",
    "run_deep_tools",
]
