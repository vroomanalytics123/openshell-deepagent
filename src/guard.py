"""Command-layer guard for the agent's execute() path.

Why this exists (measured with FinePrint against this repo's real command
surface): the agent runs every command through `bash -c` (see
backend.py), and there is no command-layer decision or approval anywhere
in this repo — safety rests entirely on the OpenShell sandbox policy
(filesystem Landlock rules, network allowlists, non-root user). This
guard adds a narrow, high-confidence Decision layer in front of
execute(): it refuses only recursive, forced deletes whose targets
resolve outside the writable directories declared in policy.yaml
(read_write: /sandbox, /tmp, /workspace). Everything else passes
through unchanged.

Deliberate limits (read before extending):
- Lexical path resolution only: `..` segments are resolved textually,
  so a symlink inside a writable directory that points outside is NOT
  caught here — the sandbox policy remains the real boundary for that.
- Unparseable input fails OPEN (allowed): a command we cannot parse
  with confidence is the sandbox's problem, never a reason to break a
  legitimate agent run.
- `~` and `$VAR` targets are unresolvable lexically, so they fail open
  too. Extending this guard means resolving against the live sandbox
  filesystem, not adding more string matching.
- Scope is `rm` with recursive + force flags only. Reads, writes,
  network use, and all other commands are the sandbox policy's job.
"""

from __future__ import annotations

import posixpath
import shlex

# Mirrors policy.yaml filesystem_policy.read_write. Keep in sync with it.
WRITABLE_DIRS = ("/sandbox", "/tmp", "/workspace")

# The agent's working directory: relative targets resolve against it.
WORKDIR = "/sandbox"


def _split_top_level(command: str) -> list[str] | None:
    """Split on ;, &&, ||, |, & outside quotes. None if unbalanced."""
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(command):
        ch = command[i]
        if quote is not None:
            buf.append(ch)
            if ch == quote:
                quote = None
            elif ch == "\\" and i + 1 < len(command):
                buf.append(command[i + 1])
                i += 1
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == "\\" and i + 1 < len(command):
            buf.append(ch)
            buf.append(command[i + 1])
            i += 1
        elif ch == ";":
            segments.append("".join(buf))
            buf = []
        elif ch in ("&", "|"):
            if command[i:i + 2] in ("&&", "||"):
                i += 1
            segments.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    if quote is not None:
        return None
    segments.append("".join(buf))
    return segments


def _is_inside(path: str) -> bool:
    return any(path == d or path.startswith(d + "/") for d in WRITABLE_DIRS)


def _resolve_target(target: str) -> str | None:
    """Lexically resolve a target. None if unresolvable (fail open)."""
    if target.startswith("~") or "$" in target:
        return None
    if posixpath.isabs(target):
        return posixpath.normpath(target)
    return posixpath.normpath(posixpath.join(WORKDIR, target))


def _segment_refusal(segment: str) -> str | None:
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        return None  # fail open on unparseable input
    if not tokens:
        return None
    if posixpath.basename(tokens[0]) != "rm":
        return None
    recursive = False
    force = False
    targets: list[str] = []
    flags_done = False
    for tok in tokens[1:]:
        if not flags_done and tok == "--":
            flags_done = True
            continue
        if not flags_done and tok.startswith("--"):
            if tok == "--recursive":
                recursive = True
            elif tok == "--force":
                force = True
            # Any other long flag is not a target; ignore it.
            continue
        if not flags_done and len(tok) > 1 and tok.startswith("-") and tok[1:].isalpha():
            letters = tok[1:]
            if "r" in letters or "R" in letters:
                recursive = True
            if "f" in letters:
                force = True
            continue
        targets.append(tok)
    if not (recursive and force):
        return None
    for target in targets:
        resolved = _resolve_target(target)
        if resolved is None:
            continue  # unresolvable target: fail open for it
        if not _is_inside(resolved):
            return (
                f"'{segment.strip()}' would recursively force-delete "
                f"'{target}' (resolves to '{resolved}'), which is outside "
                f"the agent's writable directories "
                f"({', '.join(WRITABLE_DIRS)}). Delete inside a writable "
                f"directory instead, or adjust the sandbox policy if this "
                f"path should be writable."
            )
    return None


def refusal_reason(command: str) -> str | None:
    """Return a refusal message if the command must not run, else None.

    Only high-confidence destructive deletes outside writable directories
    are refused. Everything else returns None (allowed through).
    """
    segments = _split_top_level(command)
    if segments is None:
        return None  # unbalanced quotes: fail open
    for segment in segments:
        reason = _segment_refusal(segment)
        if reason is not None:
            return reason
    return None
