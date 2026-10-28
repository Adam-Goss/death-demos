"""Helpers shared by the operator commands (issue #24): plan, state directory, refusals, JSON over HTTP."""
import json
import os
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


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
