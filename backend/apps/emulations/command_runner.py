"""
Playbook command runner — safely execute read-only AWS CLI commands.

A playbook lists AWS CLI commands an analyst runs during an incident. This
module lets the backend run the read-only ones against the user's account using
their assumed role, so the analyst gets live output without leaving the app.

Security model (why this is safe):

  * Allowlist, not blocklist. Only an explicitly curated set of read-only,
    non-secret operations (SAFE_OPS) may run. Everything else is rejected and
    stays copy-only in the UI. "Read-only" is not the same as "safe to display",
    so secret-returning reads (GetSecretValue, GetParameter --with-decryption,
    KMS Decrypt, session tokens) are deliberately absent from the allowlist.
  * No shell, ever. A command is parsed to an argv list and executed by exec-ing
    the aws binary directly (subprocess without shell=True). Shell metacharacters
    (pipes, $(...), backticks, &&, ;, redirects) cause a hard reject, so there is
    no command-injection surface.
  * No unresolved placeholders. A command still containing a <placeholder> or an
    unresolved $VAR is not runnable; the caller surfaces it as copy-only.

The functions here are pure (no Django, no network) so they are unit-testable in
isolation; the view layer wires them to STS credentials and audit logging.
"""

from __future__ import annotations

import difflib
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field

# Minimum similarity for a placeholder to bind to a stack-output key. Below this
# the placeholder stays unresolved (copy-only) rather than risk a wrong fill.
_MATCH_THRESHOLD = 0.62

# Curated allowlist of safe, read-only, non-secret CLI operations per service.
# Keys are `aws <service>` names; values are the kebab-case operation names.
# Only pairs listed here can ever be executed. Grow this deliberately.
SAFE_OPS: dict[str, frozenset[str]] = {
    "sts": frozenset({"get-caller-identity"}),
    "cloudtrail": frozenset({
        "lookup-events", "get-trail-status", "describe-trails",
        "get-event-selectors", "list-trails",
    }),
    "ec2": frozenset({
        "describe-instances", "describe-security-groups", "describe-security-group-rules",
        "describe-images", "describe-vpcs", "describe-subnets",
        "describe-network-interfaces", "describe-addresses", "describe-instance-attribute",
    }),
    "iam": frozenset({
        "list-users", "list-roles", "list-access-keys", "get-user",
        "list-attached-user-policies", "list-attached-role-policies",
        "list-user-policies", "list-role-policies", "list-groups-for-user",
        "get-account-authorization-details",
    }),
    "s3api": frozenset({
        "list-buckets", "list-objects-v2", "list-objects", "list-object-versions",
        "head-object", "get-bucket-versioning", "get-bucket-lifecycle-configuration",
        "get-bucket-policy", "get-bucket-acl", "get-bucket-encryption",
    }),
    "guardduty": frozenset({
        "list-detectors", "get-detector", "list-findings", "get-findings", "list-members",
    }),
    "ecs": frozenset({
        "list-clusters", "describe-clusters", "list-task-definitions",
        "describe-task-definition", "list-tasks", "describe-tasks", "list-services",
    }),
    "sagemaker": frozenset({"list-notebook-instances", "describe-notebook-instance"}),
    "secretsmanager": frozenset({"list-secrets", "describe-secret"}),
    "ssm": frozenset({"describe-instance-information", "describe-parameters"}),
    "logs": frozenset({
        "describe-log-groups", "describe-log-streams", "filter-log-events",
    }),
}

# Any of these in the raw block means it is not a single clean CLI call. A shell
# would be needed to evaluate them, and we never invoke a shell.
_SHELL_CONSTRUCTS = ("|", "$(", "`", "&&", "||", ";", ">>", " > ", " < ")

# Characters that must never appear inside a resolved argv token.
_METACHAR_RE = re.compile(r"[;|&`$><(){}\\\n]")

# An unfilled placeholder, e.g. <victim-iam-username>.
_PLACEHOLDER_RE = re.compile(r"<[^>]+>")

# A shell variable reference: $VAR or ${VAR}.
_VARREF_RE = re.compile(r"\$\{?(\w+)\}?")

# A simple VAR=value assignment line.
_ASSIGN_RE = re.compile(r'^(\w+)=(.*)$')


@dataclass
class ParsedCommand:
    """Result of parsing a playbook code block into a runnable command."""

    argv: list[str] = field(default_factory=list)
    # Placeholders/variables that could not be resolved (block is not runnable).
    unresolved: list[str] = field(default_factory=list)
    # Non-empty when the block cannot be turned into a single safe CLI call.
    error: str | None = None

    @property
    def runnable(self) -> bool:
        return self.error is None and not self.unresolved and bool(self.argv)


def parse_command(block: str) -> ParsedCommand:
    """
    Parse a playbook code block into a single `aws` argv, resolving inline vars.

    Handles the common shape of a playbook snippet: a few `VAR="value"`
    assignment lines, comments, and one `aws ...` invocation (possibly split
    across lines with trailing backslashes). Returns a ParsedCommand whose
    `error` is set if the block is not a single, shell-free CLI call, and whose
    `unresolved` lists any placeholders/vars still missing a value.
    """
    if any(tok in block for tok in _SHELL_CONSTRUCTS):
        return ParsedCommand(error="Command uses shell features that can't be run automatically.")

    # Collect VAR=value assignments and the aws invocation, ignoring comments.
    assignments: dict[str, str] = {}
    aws_lines: list[str] = []
    collecting_aws = False

    for raw in block.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if collecting_aws:
            aws_lines.append(line.rstrip("\\").strip())
            collecting_aws = raw.rstrip().endswith("\\")
            continue
        if line.startswith("aws "):
            aws_lines.append(line.rstrip("\\").strip())
            collecting_aws = raw.rstrip().endswith("\\")
            continue
        m = _ASSIGN_RE.match(line)
        if m:
            assignments[m.group(1)] = m.group(2).strip().strip('"').strip("'")

    if not aws_lines:
        return ParsedCommand(error="No aws command found in this block.")

    command_str = " ".join(aws_lines)
    try:
        tokens = shlex.split(command_str)
    except ValueError:
        return ParsedCommand(error="Command could not be parsed.")

    # Substitute $VAR references from the block's own assignments. A reference
    # with no matching assignment is left in place and later flagged unresolved.
    unresolved: list[str] = []
    resolved: list[str] = []
    for tok in tokens:
        def _sub(match: re.Match[str]) -> str:
            name = match.group(1)
            if name in assignments:
                return assignments[name]
            unresolved.append(f"${name}")
            return match.group(0)

        resolved.append(_VARREF_RE.sub(_sub, tok))

    parsed = ParsedCommand(argv=resolved, unresolved=unresolved)
    # Placeholders are collected here but only make the command non-runnable;
    # stack-output resolution (resolve_from_stack) may still fill them.
    for tok in resolved:
        parsed.unresolved.extend(_PLACEHOLDER_RE.findall(tok))
    return parsed


def resolve_from_stack(parsed: ParsedCommand, outputs: dict) -> ParsedCommand:
    """
    Fill remaining <placeholders>/$vars from a deployed stack's outputs.

    Because MayaTrail deployed the emulation, the real resource names live in the
    stack outputs. A placeholder binds to the output key with the highest name
    similarity (normalised to lowercase alphanumerics), and only if that best
    score clears _MATCH_THRESHOLD. Requiring the *best* match above a threshold,
    rather than the first containment hit, avoids filling a wrong resource name
    for names like <victim-iam-username> -> victim_user_name; anything that stays
    below the bar is left unresolved and the command remains copy-only.
    """
    if not parsed.unresolved or parsed.error:
        return parsed

    def _norm(text: str) -> str:
        return re.sub(r"[^a-z0-9]", "", text.lower())

    norm_outputs = {_norm(k): str(v) for k, v in (outputs or {}).items() if isinstance(v, (str, int))}

    def _best(name: str) -> str | None:
        key = _norm(name)
        best_val: str | None = None
        best_score = 0.0
        for out_key, out_val in norm_outputs.items():
            if not key or not out_key:
                continue
            score = 1.0 if (key in out_key or out_key in key) else difflib.SequenceMatcher(None, key, out_key).ratio()
            if score > best_score:
                best_score, best_val = score, out_val
        return best_val if best_score >= _MATCH_THRESHOLD else None

    new_argv: list[str] = []
    still_unresolved: list[str] = []
    for tok in parsed.argv:
        def _fill(match: re.Match[str]) -> str:
            val = _best(match.group(0).strip("<>$"))
            if val is None:
                still_unresolved.append(match.group(0))
                return match.group(0)
            return val

        tok = _PLACEHOLDER_RE.sub(_fill, tok)
        tok = _VARREF_RE.sub(lambda m: _best(m.group(1)) or m.group(0), tok)
        new_argv.append(tok)

    return ParsedCommand(argv=new_argv, unresolved=still_unresolved, error=parsed.error)


def validate_argv(argv: list[str]) -> str | None:
    """
    Final gate before execution. Returns an error string, or None if safe.

    Enforces: it is an `aws <service> <op>` call; the (service, op) pair is in the
    read-only allowlist; no token carries a shell metacharacter or leftover
    placeholder. This is authoritative regardless of anything the client claimed.
    """
    if len(argv) < 3 or argv[0] != "aws":
        return "Only a single 'aws <service> <operation>' command can be run."
    service, operation = argv[1], argv[2]
    allowed = SAFE_OPS.get(service)
    if not allowed or operation not in allowed:
        return f"'{service} {operation}' is not in the read-only allowlist; copy it to run locally."
    for tok in argv:
        if _METACHAR_RE.search(tok) or _PLACEHOLDER_RE.search(tok):
            return "Command still contains an unresolved value or unsafe character."
    return None


def run_argv(
    argv: list[str],
    creds: dict[str, str],
    region: str,
    timeout: int = 20,
    max_output: int = 20000,
) -> tuple[int, str, str]:
    """
    Execute a validated argv by exec-ing the aws binary directly (no shell).

    Credentials are injected via the environment for this single call only. The
    caller must have run validate_argv() first. Output is truncated to bound the
    response size.
    """
    aws_bin = shutil.which("aws")
    if not aws_bin:
        return 127, "", "aws CLI is not available on the server."

    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "AWS_ACCESS_KEY_ID": creds["AWS_ACCESS_KEY_ID"],
        "AWS_SECRET_ACCESS_KEY": creds["AWS_SECRET_ACCESS_KEY"],
        "AWS_SESSION_TOKEN": creds["AWS_SESSION_TOKEN"],
        "AWS_DEFAULT_REGION": region or "us-east-1",
        # Never page into an interactive viewer inside a subprocess.
        "AWS_PAGER": "",
    }
    try:
        proc = subprocess.run(
            [aws_bin, *argv[1:]],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s."

    return proc.returncode, proc.stdout[:max_output], proc.stderr[:max_output]
