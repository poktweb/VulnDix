#!/usr/bin/env bash
# Instala binários em third_party/linux-amd64 (Linux primário)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 vulndix.py --install-tools
