"""Tests for the init subcommand."""

import argparse
import json
from pathlib import Path

import pytest

from cc_audit.cli import cmd_init, hook_command


def _cc_audit_entries(settings_path: Path) -> list[str]:
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    return [
        str(hook.get("command"))
        for entry in settings.get("hooks", {}).get("PreToolUse", [])
        for hook in entry.get("hooks", [])
        if "-m cc_audit.hook" in str(hook.get("command", ""))
    ]


def test_init_twice_yields_single_hook_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    settings_path = tmp_path / ".claude" / "settings.json"

    assert cmd_init(argparse.Namespace()) == 0
    assert _cc_audit_entries(settings_path) == [hook_command()]

    assert cmd_init(argparse.Namespace()) == 0
    assert _cc_audit_entries(settings_path) == [hook_command()]


def test_init_updates_stale_entry_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir()
    settings_path.write_text(
        json.dumps(
            {
                "model": "keep-me",
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "*",
                            "hooks": [
                                {"type": "command", "command": "old-python -m cc_audit.hook"}
                            ],
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    assert cmd_init(argparse.Namespace()) == 0
    assert _cc_audit_entries(settings_path) == [hook_command()]
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    assert settings["model"] == "keep-me"
    # Backup of the original was kept.
    assert list(settings_path.parent.glob("settings.json.bak-*"))
