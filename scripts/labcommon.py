"""Helpers shared by the operator commands (issue #24): plan, state directory, refusals, JSON over HTTP, the bash to spawn repo scripts with."""
import json
import os
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Where Git for Windows puts the bash that can open a C:/ path, most common install first.
GIT_BASH = ("C:/Program Files/Git/bin/bash.exe", "C:/Program Files (x86)/Git/bin/bash.exe")


def resolve_bash(os_name=None, candidates=GIT_BASH, env=None):
    """The bash to spawn repo scripts with (#69).

    A bare "bash" from a Python subprocess on Windows is `bash.exe` in System32, the WSL launcher, which cannot
    open a `C:/...` path: it fails before the script runs. Prefer Git Bash there. Set OPALEYE_BASH to override
    (a Git install outside the two usual places). Everywhere else "bash" off PATH is right.

    Falling back to "bash" on a Windows box with no Git Bash restores the original failure rather than refusing:
    the callers report it themselves, and README says which to install. The arguments are injection seams for
    the tests, so the Windows branch can be exercised from Linux.
    """
    os_name = os.name if os_name is None else os_name
    env = os.environ if env is None else env
    override = env.get("OPALEYE_BASH")
    if override:
        return override
    if os_name != "nt":
        return "bash"
    return next((b for b in candidates if os.path.exists(b)), "bash")


# Resolved once: the platform cannot change under a running process, and OPALEYE_BASH is read at startup.
BASH = resolve_bash()


def die(msg):
    raise SystemExit("refused: " + msg)


def load_plan():
    with open(os.environ.get("LAB_PLAN", os.path.join(ROOT, "network/plan.json"))) as f:
        return json.load(f)


def state_dir():
    d = os.environ.get("LABMODE_STATE_DIR", ".state")
    os.makedirs(d, exist_ok=True)
    return d


def fetch_json(url, method="GET", headers=None, body=None, ctx=None):
    """One JSON request; raises on any HTTP or transport failure (callers wrap it in their own error type)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        raw = r.read()
    return json.loads(raw) if raw else {}


def active_exercise(state):
    """The exercise recorded as open in the workstation state (labops.py owns it), or None."""
    try:
        with open(os.path.join(state, "labops.json")) as f:
            return json.load(f).get("active")
    except FileNotFoundError:
        return None
