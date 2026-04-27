#!/bin/bash
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# Install Mach-O / ARM64 analysis libraries if not already present
pip3 install --quiet --disable-pip-version-check \
  lief \
  capstone \
  keystone-engine

# Print tool summary so Claude knows what's available
python3 - <<'PYEOF'
import shutil, sys

tools = [
    ("strings",     "extract string constants from binaries"),
    ("nm",          "list symbols from object files"),
    ("objdump",     "disassemble and inspect binaries"),
    ("readelf",     "display ELF / binary section info"),
    ("grep",        "binary string search (use -a flag)"),
    ("perl",        "binary patching via -pi -e"),
    ("dpkg-deb",    "extract .deb packages"),
    ("python3",     "scripting / hex patching"),
    ("file",        "identify file types"),
    ("git",         "version control"),
    ("make",        "build system (Theos)"),
    ("clang",       "C/ObjC compiler"),
    ("dpkg",        "package manager"),
]

try:
    import lief
    lief_ver = lief.__version__
except ImportError:
    lief_ver = None

try:
    import capstone
    cs_ver = capstone.__version__
except ImportError:
    cs_ver = None

try:
    import keystone
    ks_ver = "ok"
except ImportError:
    ks_ver = None

print("\n=== YTLite Session Ready ===")
print("\nBinary analysis tools:")
for name, desc in tools:
    status = "✓" if shutil.which(name) else "✗"
    print(f"  {status} {name:<16} {desc}")

print("\nPython RE libraries:")
print(f"  {'✓' if lief_ver else '✗'} lief              {'v' + lief_ver if lief_ver else 'NOT installed'} — Mach-O parser, Obj-C class/method enumeration")
print(f"  {'✓' if cs_ver else '✗'} capstone          {'v' + cs_ver if cs_ver else 'NOT installed'} — ARM64 disassembler")
print(f"  {'✓' if ks_ver else '✗'} keystone-engine   {'ready' if ks_ver else 'NOT installed'} — ARM64 assembler (patch byte generation)")

print("\nProject: /home/user/YTLite  |  Repo: the-big-mini/ytlite")
print("Task: patch Patreon DRM from v5.2.1 binary OR forward-port features to source")
print("See CLAUDE.md for full context, tool usage examples, and Logos syntax reference.\n")
PYEOF

# Run Logos static checker
echo "Logos static check:"
python3 "$(dirname "$0")/logos-check.py" && echo "  All .x files clean" || echo "  Issues found — review before building"
