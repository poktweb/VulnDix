#!/usr/bin/env python3
"""Atalho: força download de payloads (mesmo que vulndix.py --update-payloads)."""
from __future__ import annotations

import sys

from vulndix.payload_updater import update_payloads
from vulndix.reporter import eprint

if __name__ == "__main__":
    eprint("[*] Atualização manual de payloads...")
    counts = update_payloads(max_per_category=500)
    raise SystemExit(0 if sum(counts.values()) > 0 else 1)
