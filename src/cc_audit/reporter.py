"""Markdown session reports from JSONL audit logs."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from cc_audit.logger import AUDIT_DIR_NAME, read_events

PATH_TOOLS = ("Read", "Write", "Edit")
SHELL_TOOLS = ("Bash", "PowerShell")
# log_only events were not stopped, so they did execute.
EXECUTED_DECISIONS = ("allowed", "log_only")


def find_session_files(
    root: Path, session: str | None = None, all_sessions: bool = False
) -> list[Path]:
    """Resolve which session files to report on.

    Default is the newest session; ``session`` selects by substring of the
    file name; ``all_sessions`` selects everything.
    """
    directory = Path(root) / AUDIT_DIR_NAME
    files = sorted(directory.glob("session-*.jsonl"), key=lambda p: p.stat().st_mtime)
    if not files:
        return []
    if all_sessions:
        return files
    if session:
        matches = [f for f in files if session in f.stem]
        return matches
    return [files[-1]]


def generate_report(
    root: Path, session: str | None = None, all_sessions: bool = False
) -> str:
    root = Path(root)
    files = find_session_files(root, session=session, all_sessions=all_sessions)
    lines = ["# cc-audit report", ""]
    if not files:
        lines.append("_No matching session logs found in .cc-audit/._")
        return "\n".join(lines)
    for path in files:
        lines.extend(_session_section(root, path))
    return "\n".join(lines)


def _session_section(root: Path, path: Path) -> list[str]:
    events = read_events(path)
    lines = [f"## Session `{path.name}`", ""]
    if not events:
        lines.extend(["_No events recorded._", ""])
        return lines

    decisions = Counter(e.get("decision") for e in events)
    tools = Counter(e.get("tool_name") for e in events)
    timestamps = [e["timestamp"] for e in events if e.get("timestamp")]

    lines.append("### Summary")
    lines.append("")
    if timestamps:
        lines.append(f"- Time range: {min(timestamps)} → {max(timestamps)}")
    lines.append(f"- Events: {len(events)}")
    lines.append(
        "- Decisions: "
        + ", ".join(f"{name}: {count}" for name, count in sorted(decisions.items()))
    )
    lines.append(
        "- Tools: " + ", ".join(f"{name} ({count})" for name, count in tools.most_common())
    )
    lines.append("")

    path_events = [e for e in events if e.get("tool_name") in PATH_TOOLS and e.get("target")]
    file_events = [e for e in path_events if e.get("decision") in EXECUTED_DECISIONS]
    lines.append("### Files touched")
    lines.append("")
    if file_events:
        counts: Counter[str] = Counter()
        tools_per_file: dict[str, set[str]] = {}
        for e in file_events:
            target = str(e["target"])
            counts[target] += 1
            tools_per_file.setdefault(target, set()).add(str(e.get("tool_name")))
        for target, count in counts.most_common():
            tool_list = ", ".join(sorted(tools_per_file[target]))
            lines.append(f"- `{target}` — {count}x ({tool_list})")
    else:
        lines.append("_None._")
    lines.append("")

    commands = Counter(
        str(e["target"])
        for e in events
        if e.get("tool_name") in SHELL_TOOLS
        and e.get("target")
        and e.get("decision") in EXECUTED_DECISIONS
    )
    lines.append("### Commands executed")
    lines.append("")
    if commands:
        for command, count in commands.most_common():
            suffix = f" — {count}x" if count > 1 else ""
            lines.append(f"- `{command}`{suffix}")
    else:
        lines.append("_None._")
    lines.append("")

    blocked = [e for e in events if e.get("decision") in ("blocked", "log_only", "policy-error")]
    lines.append("### Blocked attempts")
    lines.append("")
    if blocked:
        for e in blocked:
            lines.append(
                f"- ⚠️ **{str(e.get('decision')).upper()}** {e.get('tool_name')} "
                f"`{e.get('target')}` (rule: `{e.get('rule')}`) at {e.get('timestamp')}"
            )
    else:
        lines.append("_None._")
    lines.append("")

    lines.append("### Anomalies (access outside project root)")
    lines.append("")
    anomalies = _find_anomalies(root, path_events)
    if anomalies:
        for (target, decision), count in anomalies.most_common():
            lines.append(f"- ⚠️ `{target}` — {decision}, {count}x")
    else:
        lines.append("_None._")
    lines.append("")
    return lines


def _find_anomalies(root: Path, path_events: list[dict]) -> Counter:
    """Count out-of-root path accesses, keyed by (target, decision)."""
    try:
        root_resolved = root.resolve()
    except OSError:
        root_resolved = root
    anomalies: Counter[tuple[str, str]] = Counter()
    for e in path_events:
        target = str(e["target"])
        try:
            resolved = Path(target).expanduser()
            if not resolved.is_absolute():
                resolved = root_resolved / resolved
            resolved = resolved.resolve()
        except OSError:
            continue
        if not resolved.is_relative_to(root_resolved):
            anomalies[(target, str(e.get("decision")))] += 1
    return anomalies
