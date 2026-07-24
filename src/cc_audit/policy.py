"""Policy loading and matching.

Loads audit-policy.yaml from the project root, falling back to built-in
defaults when the file is missing. If the file exists but cannot be parsed
(or contains an invalid regex), the policy FAILS CLOSED: the built-in
defaults are enforced and ``Policy.error`` carries the parse error so the
hook can log a policy-error event.

Parsed policies are cached in-process, keyed by file path and mtime, so
repeated hook invocations within one interpreter avoid re-reading the file.
PyYAML is imported lazily so the hook stays fast on the allow path.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

POLICY_FILENAME = "audit-policy.yaml"

DEFAULT_BLOCKED_PATHS: tuple[str, ...] = (
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/credentials*",
    "~/.ssh/**",
)

DEFAULT_BLOCKED_COMMANDS: tuple[str, ...] = (
    # rm -rf (any flag order) aimed at root-ish paths.
    r"\brm\s+(?:-[a-zA-Z]+\s+)*-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)"
    r"[a-zA-Z]*\s+[\"']?(?:/|~|\$HOME|%USERPROFILE%|[A-Za-z]:[\\/])[\"']?\s*$",
    # curl/wget shipping local data to the network.
    r"\bcurl\b[^|;&]*(?:\s-d\b|--data\S*|--upload-file|\s-T\b|\s-F\b|--form)",
    r"\bwget\b[^|;&]*(?:--post-data|--post-file|--body-data|--body-file)",
    # PowerShell-native exfiltration.
    r"\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^|;&]*"
    r"(?:-Body\b|-InFile\b|-Method\s+Post\b)",
)


# Shell metacharacters and quotes that separate arguments; splitting on these
# turns a command into candidate path tokens for the blocked-path scan.
_COMMAND_TOKEN_SPLIT = re.compile(r"""[\s;|&<>()'"`,=]+""")


def _command_path_tokens(command: str) -> list[str]:
    """Pull filename-like arguments out of a shell command.

    Best-effort: split on whitespace/quotes/shell metacharacters, drop flags
    and URLs, and strip a leading ``@`` (curl's ``@file`` form). Shell quoting,
    interpolation, or encoding can still hide a path — this raises the bar, it
    is not a parser.
    """
    tokens: list[str] = []
    for raw in _COMMAND_TOKEN_SPLIT.split(command):
        tok = raw.strip().lstrip("@")
        if not tok or tok.startswith("-") or "://" in tok:
            continue
        tokens.append(tok)
    return tokens


def _path_matches(path_str: str, pattern: str) -> bool:
    """Return True if *path_str* matches the glob *pattern*.

    The path is expanded (~) and made absolute, then compared as a POSIX-style
    string; fnmatch normalises case and separators per-platform, so this is
    case-insensitive and slash-agnostic on Windows. Patterns starting with
    ``~`` are expanded against the user's home; patterns starting with ``**/``
    also match at zero directory depth.
    """
    pat = pattern
    if pat.startswith("~"):
        pat = Path(pat).expanduser().as_posix()
    target = Path(str(path_str)).expanduser()
    if not target.is_absolute():
        target = Path.cwd() / target
    # Collapse "." and ".." lexically so a traversal (foo/../.env) cannot dodge
    # an absolute rule; normpath is purely textual, so it never touches the disk.
    candidate = Path(os.path.normpath(target)).as_posix()
    if fnmatch.fnmatch(candidate, pat):
        return True
    if pat.startswith("**/") and fnmatch.fnmatch(candidate, pat[3:]):
        return True
    return False


@dataclass(frozen=True)
class Policy:
    """An immutable, validated audit policy ready for matching."""

    blocked_paths: tuple[str, ...] = DEFAULT_BLOCKED_PATHS
    blocked_commands: tuple[str, ...] = DEFAULT_BLOCKED_COMMANDS
    log_only: bool = False
    error: str | None = None
    source: str = "defaults"
    _command_res: tuple[re.Pattern[str], ...] = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        compiled = tuple(re.compile(p, re.IGNORECASE) for p in self.blocked_commands)
        object.__setattr__(self, "_command_res", compiled)

    def _decision(self) -> str:
        return "log_only" if self.log_only else "blocked"

    def check_path(self, path: str) -> tuple[str, str | None]:
        """Return (decision, matched_rule) for a file path target."""
        for pattern in self.blocked_paths:
            if _path_matches(path, pattern):
                return self._decision(), pattern
        return "allowed", None

    def check_command(self, command: str) -> tuple[str, str | None]:
        """Return (decision, matched_rule) for a shell command string.

        Two checks: the exfiltration regexes in ``blocked_commands``, and a scan
        for any ``blocked_paths`` entry referenced as a command argument. The
        second closes the gap where a shell read (``cat .env``, ``Get-Content
        .env``) would otherwise slip past the path rules that only guard the
        Read/Write/Edit tools. The matched rule is returned either way.
        """
        for pattern, regex in zip(self.blocked_commands, self._command_res):
            if regex.search(command):
                return self._decision(), pattern
        for token in _command_path_tokens(command):
            for pattern in self.blocked_paths:
                if _path_matches(token, pattern):
                    return self._decision(), pattern
        return "allowed", None


_cache: dict[tuple[str, int | None], Policy] = {}


def load_policy(root: Path | str | None = None) -> Policy:
    """Load the policy for *root* (default: cwd), with in-process caching.

    Missing file -> defaults. Unparseable file or invalid regex -> defaults
    with ``error`` set (fail-closed).
    """
    root_path = Path(root) if root is not None else Path.cwd()
    policy_file = root_path / POLICY_FILENAME
    try:
        mtime: int | None = policy_file.stat().st_mtime_ns
    except OSError:
        mtime = None
    key = (str(policy_file), mtime)
    cached = _cache.get(key)
    if cached is not None:
        return cached

    policy = _load_uncached(policy_file, exists=mtime is not None)
    _cache[key] = policy
    return policy


def _load_uncached(policy_file: Path, exists: bool) -> Policy:
    if not exists:
        return Policy(source="defaults")

    try:
        import yaml

        data = yaml.safe_load(policy_file.read_text(encoding="utf-8"))
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ValueError(f"policy root must be a mapping, got {type(data).__name__}")

        blocked_paths = _str_tuple(data.get("blocked_paths"), DEFAULT_BLOCKED_PATHS)
        blocked_commands = _str_tuple(data.get("blocked_commands"), DEFAULT_BLOCKED_COMMANDS)
        for pattern in blocked_commands:
            re.compile(pattern, re.IGNORECASE)
        return Policy(
            blocked_paths=blocked_paths,
            blocked_commands=blocked_commands,
            log_only=bool(data.get("log_only", False)),
            source=str(policy_file),
        )
    except Exception as exc:  # fail closed on any parse/validation problem
        return Policy(error=f"{type(exc).__name__}: {exc}", source=str(policy_file))


def _str_tuple(value: object, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError("blocked_paths/blocked_commands must be lists of strings")
    return tuple(value)
