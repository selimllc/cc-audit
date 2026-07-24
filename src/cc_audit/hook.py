"""PreToolUse hook entry point.

Invoked by Claude Code as ``python -m cc_audit.hook``. Reads the hook
payload JSON from stdin, checks the target against the policy, logs the
event, and exits 2 with a reason on stderr to block, or 0 to allow.

Internal failures (broken stdin, unwritable log directory, ...) are
reported on stderr but exit 0 so a bug in the auditor cannot brick the
session; policy-file failures are handled fail-closed in policy.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PATH_TOOLS = frozenset({"Read", "Write", "Edit"})
SEARCH_TOOLS = frozenset({"Glob", "Grep"})


def _scalar_summary(tool_input: dict) -> str:
    """Compact single-line summary of the payload's scalar fields."""
    parts = [
        f"{key}={value}"
        for key, value in tool_input.items()
        if isinstance(value, (str, int, float, bool))
    ]
    summary = " ".join(parts) or "(no input)"
    return " ".join(summary.split())[:300]


def extract_target(tool_name: str, tool_input: dict) -> tuple[str, str | None]:
    """Return (target, kind) where kind is "path", "command", or None.

    Every tool gets a non-empty target: path tools use file_path, search
    tools use pattern, and any tool whose payload carries a command field
    (Bash, PowerShell, ...) is treated as a shell command. Anything else
    falls back to a scalar summary of the payload.
    """
    if tool_name in PATH_TOOLS:
        file_path = tool_input.get("file_path")
        if file_path:
            return str(file_path), "path"
    elif tool_name in SEARCH_TOOLS:
        pattern = tool_input.get("pattern")
        if pattern:
            path = tool_input.get("path")
            return (f"{pattern} in {path}" if path else str(pattern)), None
    command = tool_input.get("command")
    if isinstance(command, str) and command:
        return command, "command"
    return _scalar_summary(tool_input), None


def run(payload: dict) -> int:
    from cc_audit import logger
    from cc_audit.policy import POLICY_FILENAME, load_policy

    tool_name = str(payload.get("tool_name") or "unknown")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    session_id = payload.get("session_id")
    root = Path(payload.get("cwd") or Path.cwd())

    policy = load_policy(root)
    if policy.error:
        logger.log_event(
            root, session_id, "cc-audit", str(root / POLICY_FILENAME), "policy-error", policy.error
        )

    target, kind = extract_target(tool_name, tool_input)
    if kind == "path":
        decision, rule = policy.check_path(target)
    elif kind == "command":
        decision, rule = policy.check_command(target)
    else:
        decision, rule = "allowed", None

    logger.log_event(root, session_id, tool_name, target, decision, rule)

    if decision == "blocked":
        print(f"cc-audit: blocked {tool_name} on {target} (rule: {rule})", file=sys.stderr)
        return 2
    return 0


def main() -> int:
    try:
        raw = sys.stdin.read().lstrip("﻿")
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            payload = {}
        return run(payload)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"cc-audit: internal error, allowing tool call: {exc}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())
