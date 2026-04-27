#!/bin/bash
# YTLite Session Start Hook
# Installs analysis libs, prints tool/git state, runs Logos checker.
set -uo pipefail

export GIT_OPTIONAL_LOCKS=0

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
CLAUDE_DIR="$REPO_ROOT/.claude"
BRANCH_FILE="$CLAUDE_DIR/.current-branch"

# ── auto-checkout stored session branch ──────────────────────────────────────
STORED_BRANCH=""
[[ -f "$BRANCH_FILE" ]] && STORED_BRANCH="$(tr -d '[:space:]' < "$BRANCH_FILE" 2>/dev/null || true)"

CURRENT_BRANCH="$(git branch --show-current 2>/dev/null || echo '')"
BRANCH_ACTION=""

if [[ -n "$STORED_BRANCH" ]] && git show-ref --verify --quiet "refs/heads/$STORED_BRANCH"; then
  if [[ "$CURRENT_BRANCH" == "$STORED_BRANCH" ]]; then
    BRANCH_ACTION="Already on session branch '$STORED_BRANCH'"
  elif git diff --quiet && git diff --cached --quiet; then
    if git checkout "$STORED_BRANCH" >/dev/null 2>&1; then
      BRANCH_ACTION="Resumed: checked out '$STORED_BRANCH'"
    else
      BRANCH_ACTION="Checkout failed — staying on '$CURRENT_BRANCH'"
    fi
  else
    BRANCH_ACTION="WARNING: Uncommitted changes prevent auto-checkout of '$STORED_BRANCH'"
  fi
else
  BRANCH_ACTION="New session — no stored branch. Create one and write to .claude/.current-branch"
fi

BRANCH="$(git branch --show-current 2>/dev/null || echo 'unknown')"

# ── git state ─────────────────────────────────────────────────────────────────
truncate_list() { tr '\n' ' ' | sed 's/ $//'; }

UNPUSHED="$(git rev-list "origin/${BRANCH}..HEAD" --count 2>/dev/null || echo '?')"
DIRTY="$(git diff --name-only HEAD 2>/dev/null | head -10 | truncate_list)"
STAGED="$(git diff --cached --name-only 2>/dev/null | head -10 | truncate_list)"
UNTRACKED="$(git ls-files --others --exclude-standard 2>/dev/null | head -5 | truncate_list)"
RECENT="$(git log -6 --format='  %h %s' 2>/dev/null || echo '  (none)')"

# ── version from Makefile ─────────────────────────────────────────────────────
VERSION="$(awk -F'=' '/^PACKAGE_VERSION/ {gsub(/ /,"",$2); print $2; exit}' "$REPO_ROOT/Makefile" 2>/dev/null || echo '?')"

# ── token check ───────────────────────────────────────────────────────────────
GITHUB_TOKEN_SET="false"
[[ -n "${GITHUB_TOKEN:-}" ]] && GITHUB_TOKEN_SET="true"

# ── install Python analysis libs (remote env only) ───────────────────────────
if [ "${CLAUDE_CODE_REMOTE:-}" = "true" ]; then
  pip3 install --quiet --disable-pip-version-check \
    lief \
    capstone \
    keystone-engine 2>/dev/null || true
fi

# ── print session context ─────────────────────────────────────────────────────
cat <<EOF

YTLite Session Context
======================
Project  : YTLite (Patreon-free fork — The-Big-Mini/YTLite)
Version  : $VERSION
Repo     : $REPO_ROOT
Branch   : $BRANCH
Unpushed : $UNPUSHED commit(s) ahead of origin

Branch Status: $BRANCH_ACTION

Recent Commits:
$RECENT

INSTRUCTIONS:
  - RESUMED session: continue on '$BRANCH', do not create a new branch.
  - NEW session: create one branch  claude/<description>, then run:
      echo "<branch-name>" > .claude/.current-branch
  - Never push directly to main.

Git State:
  Modified : ${DIRTY:-none}
  Staged   : ${STAGED:-none}
  Untracked: ${UNTRACKED:-none}

Environment:
  GITHUB_TOKEN set: $GITHUB_TOKEN_SET
EOF

# ── print tool readiness ──────────────────────────────────────────────────────
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
]

try:
    import lief;       lief_ver = lief.__version__
except ImportError:    lief_ver = None
try:
    import capstone;   cs_ver = capstone.__version__
except ImportError:    cs_ver = None
try:
    import keystone;   ks_ver = "ok"
except ImportError:    ks_ver = None

print("\nBinary analysis tools:")
for name, desc in tools:
    status = "+" if shutil.which(name) else "-"
    print(f"  [{status}] {name:<16} {desc}")

print("\nPython RE libraries:")
print(f"  [{'+'  if lief_ver else '-'}] lief              {'v' + lief_ver if lief_ver else 'NOT installed'} — Mach-O parser, Obj-C class/method enumeration")
print(f"  [{'+'  if cs_ver  else '-'}] capstone          {'v' + cs_ver  if cs_ver  else 'NOT installed'} — ARM64 disassembler")
print(f"  [{'+'  if ks_ver  else '-'}] keystone-engine   {'ready'       if ks_ver  else 'NOT installed'} — ARM64 assembler (patch byte generation)")

print("\nMCP tools (always available via claude code):")
mcps = [
    ("mcp__github__*",              "GitHub PR/issue/code/branch operations"),
    ("mcp__sequential-thinking__*", "Step-by-step structured reasoning"),
    ("mcp__memory__*",              "Persistent cross-session memory store"),
    ("mcp__time__*",                "Current time / timezone conversion"),
]
for name, desc in mcps:
    print(f"  [+] {name:<30} {desc}")

print()
PYEOF

# ── Logos static check ────────────────────────────────────────────────────────
echo "Logos static check:"
LOGOS_CHECKER="$(dirname "$0")/logos-check.py"
if [[ -f "$LOGOS_CHECKER" ]]; then
  python3 "$LOGOS_CHECKER" && echo "  All .x files clean" \
    || echo "  Issues found — review before building"
else
  echo "  logos-check.py not found — skipping"
fi

# ── PR reminder ───────────────────────────────────────────────────────────────
echo ""
echo "PR Notes:"
echo "  Check if a PR exists for the current branch; create one (ready for review,"
echo "  not draft) if it doesn't. Use mcp__github__create_pull_request."
