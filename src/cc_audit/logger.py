"""JSON Lines event logging.

Events are appended to ``.cc-audit/session-<stamp>.jsonl`` in the project
root, one file per Claude Code session. When the hook payload carries a
``session_id`` the file is named ``session-<YYYYMMDD-HHMMSS>-<id8>.jsonl``
(timestamp of the session's first event, plus a short sanitised id so later
events find the same file); without a session id it falls back to a
date-hour bucket ``session-<YYYYMMDD-HH>.jsonl``.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

AUDIT_DIR_NAME = ".cc-audit"
GITIGNORE_LINE = ".cc-audit/"


def audit_dir(root: Path) -> Path:
    """Return the audit directory under *root*, creating it if needed."""
    directory = Path(root) / AUDIT_DIR_NAME
    directory.mkdir(parents=True, exist_ok=True)
    _ensure_gitignore(Path(root))
    return directory


def _ensure_gitignore(root: Path) -> None:
    gitignore = root / ".gitignore"
    try:
        if gitignore.exists():
            text = gitignore.read_text(encoding="utf-8")
            if GITIGNORE_LINE in text.splitlines():
                return
            prefix = "" if (not text or text.endswith("\n")) else "\n"
            with gitignore.open("a", encoding="utf-8") as fh:
                fh.write(f"{prefix}{GITIGNORE_LINE}\n")
        else:
            gitignore.write_text(f"{GITIGNORE_LINE}\n", encoding="utf-8")
    except OSError:
        pass  # logging must not fail because .gitignore is unwritable


def _short_id(session_id: str) -> str | None:
    safe = re.sub(r"[^A-Za-z0-9_-]", "", session_id)
    return safe[:8] or None


def session_file(root: Path, session_id: str | None) -> Path:
    """Return the JSONL file for this session, stable across invocations."""
    directory = audit_dir(root)
    short = _short_id(str(session_id)) if session_id else None
    if short is None:
        stamp = datetime.now().strftime("%Y%m%d-%H")
        return directory / f"session-{stamp}.jsonl"
    existing = sorted(directory.glob(f"session-*-{short}.jsonl"))
    if existing:
        return existing[-1]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return directory / f"session-{stamp}-{short}.jsonl"


def log_event(
    root: Path,
    session_id: str | None,
    tool_name: str,
    target: str | None,
    decision: str,
    rule: str | None,
) -> None:
    """Append one audit event to the session's JSONL file."""
    event = {
        "timestamp": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "session_id": session_id,
        "tool_name": tool_name,
        "target": target,
        "decision": decision,
        "rule": rule,
    }
    path = session_file(Path(root), session_id)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")


def read_events(path: Path) -> list[dict]:
    """Read all well-formed events from one JSONL session file."""
    events: list[dict] = []
    try:
        with Path(path).open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return events
