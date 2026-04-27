#!/usr/bin/env python3
"""
Static checker for Logos (.x) source files.
Catches common mistakes before they reach the Theos build on CI.
"""
import re
import sys
from pathlib import Path


def check_file(path: Path) -> list[str]:
    issues = []
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    hook_depth = 0
    hook_open_line = None
    group_names: set[str] = set()
    inited_groups: set[str] = set()
    in_block_comment = False

    for i, raw in enumerate(lines, 1):
        line = raw.strip()

        # Track block comments so we don't flag commented-out code
        if "/*" in line:
            in_block_comment = True
        if "*/" in line:
            in_block_comment = False
            continue
        if in_block_comment or line.startswith("//"):
            continue

        # %hook ClassName
        if re.match(r"^%hook\s+\w+", line):
            if hook_depth > 0:
                issues.append(f"  line {i}: nested %hook — previous %hook (line {hook_open_line}) not closed with %end")
            hook_depth += 1
            hook_open_line = i

        # %end
        elif line == "%end":
            if hook_depth == 0:
                issues.append(f"  line {i}: stray %end with no matching %hook")
            else:
                hook_depth -= 1
                hook_open_line = None

        # %new — must be inside a %hook
        if re.match(r"^%new\b", line) and hook_depth == 0:
            issues.append(f"  line {i}: %new outside of a %hook block")

        # %orig outside a hook
        if re.search(r"%orig\b", line) and hook_depth == 0:
            # Allow in macros/defines
            if not re.match(r"^\s*#define", raw):
                issues.append(f"  line {i}: %orig used outside of a %hook block")

        # %group GroupName
        m = re.match(r"^%group\s+(\w+)", line)
        if m:
            group_names.add(m.group(1))

        # %init(GroupName) or %init(GroupName, ...) or bare %init
        for m in re.finditer(r"%init\s*\(\s*(\w+)", line):
            inited_groups.add(m.group(1))
        if re.search(r"%init\s*(?:\(|;|$)", line) and not re.search(r"%init\s*\(", line):
            inited_groups.add("__default__")

        # %ctor / %dtor should not be inside a %hook
        if re.match(r"^%(ctor|dtor)\b", line) and hook_depth > 0:
            issues.append(f"  line {i}: %ctor/%dtor inside a %hook block — should be at file scope")

    # Unclosed hooks at end of file
    if hook_depth > 0:
        issues.append(f"  {hook_depth} unclosed %hook block(s) — last opened at line {hook_open_line}")

    # %group blocks that are never %init-ed
    uninited = group_names - inited_groups
    if uninited:
        issues.append(f"  %group(s) defined but never %init-ed: {', '.join(sorted(uninited))}")

    return issues


def main():
    root = Path(__file__).parent.parent.parent  # .claude/hooks/ -> project root
    x_files = sorted(root.glob("*.x"))

    if not x_files:
        print("  (no .x files found)")
        return 0

    total_issues = 0
    for path in x_files:
        issues = check_file(path)
        if issues:
            print(f"  ✗ {path.name}")
            for issue in issues:
                print(issue)
            total_issues += len(issues)
        else:
            print(f"  ✓ {path.name}")

    return 1 if total_issues else 0


if __name__ == "__main__":
    sys.exit(main())
