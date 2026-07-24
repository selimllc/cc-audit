"""cc-audit command-line interface: init, report, tail."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

from cc_audit.logger import AUDIT_DIR_NAME


def hook_command() -> str:
    """Hook invocation pinned to the interpreter running init, quoted for spaces."""
    return f'"{sys.executable}" -m cc_audit.hook'


def cmd_init(args: argparse.Namespace) -> int:
    """Inject the PreToolUse hook into .claude/settings.json (with backup)."""
    root = Path.cwd()
    settings_path = root / ".claude" / "settings.json"
    settings: dict = {}

    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"cc-audit: cannot parse {settings_path}: {exc}", file=sys.stderr)
            print("cc-audit: refusing to modify it; fix the file and retry.", file=sys.stderr)
            return 1
        if not isinstance(settings, dict):
            print(f"cc-audit: {settings_path} is not a JSON object; refusing.", file=sys.stderr)
            return 1
        backup = settings_path.with_name(
            f"settings.json.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        )
        shutil.copy2(settings_path, backup)
        print(f"Backed up existing settings to {backup}")

    command = hook_command()
    hooks = settings.setdefault("hooks", {})
    pre_tool_use = hooks.setdefault("PreToolUse", [])
    for entry in pre_tool_use:
        for hook in entry.get("hooks", []):
            if "-m cc_audit.hook" in str(hook.get("command", "")):
                if hook.get("command") == command:
                    print(f"cc-audit hook already up to date in {settings_path}.")
                    return 0
                hook["command"] = command
                settings_path.write_text(
                    json.dumps(settings, indent=2) + "\n", encoding="utf-8"
                )
                print(f"Updated existing cc-audit hook to ({command}) in {settings_path}")
                return 0

    pre_tool_use.append(
        {
            "matcher": "*",
            "hooks": [{"type": "command", "command": command}],
        }
    )
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"Installed PreToolUse hook ({command}) in {settings_path}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from cc_audit.reporter import generate_report

    report = generate_report(Path.cwd(), session=args.session, all_sessions=args.all)
    print(report)
    return 0


def _newest_session_file(directory: Path) -> Path | None:
    files = list(directory.glob("session-*.jsonl"))
    return max(files, key=lambda p: p.stat().st_mtime) if files else None


def _print_event(line: str) -> None:
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return
    timestamp = str(event.get("timestamp", ""))[11:19]
    decision = str(event.get("decision", "?"))
    marker = "⚠️ " if decision in ("blocked", "policy-error") else ""
    print(
        f"{timestamp}  {marker}{decision.upper():<12} {str(event.get('tool_name')):<10} "
        f"{event.get('target')}"
        + (f"  [rule: {event['rule']}]" if event.get("rule") else "")
    )


def cmd_tail(args: argparse.Namespace) -> int:
    """Follow the newest session JSONL, switching if a newer one appears."""
    directory = Path.cwd() / AUDIT_DIR_NAME
    current: Path | None = None
    handle = None
    print("cc-audit: waiting for events (Ctrl+C to stop)...")
    try:
        while True:
            newest = _newest_session_file(directory) if directory.is_dir() else None
            if newest is not None and newest != current:
                if handle:
                    handle.close()
                current = newest
                handle = current.open(encoding="utf-8")
                print(f"--- following {current.name} ---")
            if handle:
                line = handle.readline()
                if line:
                    _print_event(line.strip())
                    continue
            time.sleep(0.5)
    except KeyboardInterrupt:
        return 0
    finally:
        if handle:
            handle.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cc-audit",
        description="Local security/audit layer for Claude Code.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_init = subparsers.add_parser(
        "init", help="install the PreToolUse hook into .claude/settings.json"
    )
    parser_init.set_defaults(func=cmd_init)

    parser_report = subparsers.add_parser("report", help="print a markdown session report")
    parser_report.add_argument("--session", help="session id/name substring to report on")
    parser_report.add_argument(
        "--all", action="store_true", help="report on all recorded sessions"
    )
    parser_report.set_defaults(func=cmd_report)

    parser_tail = subparsers.add_parser("tail", help="follow the newest session log live")
    parser_tail.set_defaults(func=cmd_tail)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
