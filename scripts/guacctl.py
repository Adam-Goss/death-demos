#!/usr/bin/env python3
"""Guacamole gateway provisioning (issue #51). Single source: network/plan.json.

Runs on the operator workstation over the VPN and talks to the gateway's Postgres through SSH, not the web API:
once TOTP is on, an API login needs a one-time code the script cannot have. SQL goes in on stdin, so no secret
reaches an argv. Secrets come from the operator environment, never the repo.

  guacctl.py bootstrap   replace the default guacadmin password, then (re)create the connections
  guacctl.py connections (re)create the connections only
  guacctl.py check       exit 1 if the default password still works, or TOTP is not being asked for

Env: GUAC_ADMIN_PASSWORD (>= 16 chars), ATTACKER_RDP_PASSWORD (the attacker user's RDP login; same value the attacker
role sets). The targets' SSH key is read from secrets/gateway/ (fetched by the gateway role).
TOTP is enrolled by the operator at first browser login (scan the QR code); there is no second account and no IdP.
"""
import hashlib
import json
import os
import secrets
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DEFAULT_PLAN = os.path.join(ROOT, "network", "plan.json")
ADMIN = "guacadmin"
DEFAULT_PASSWORD = "guacadmin"
KEY_FILE = os.path.join(ROOT, "secrets", "gateway", "targets_ed25519")
MIN_PASSWORD = 16


def load_plan(path=DEFAULT_PLAN):
    with open(path) as f:
        return json.load(f)


def password_hash(password, salt=None):
    """Guacamole's stored form: SHA-256 over the password followed by the salt as upper-case hex."""
    salt = secrets.token_bytes(32) if salt is None else salt
    return hashlib.sha256(password.encode() + salt.hex().upper().encode()).digest(), salt


def lit(value):
    """SQL string literal. Dollar-free, quote-doubled; NUL is refused rather than escaped."""
    if "\x00" in value:
        raise ValueError("NUL in value")
    return "'" + value.replace("'", "''") + "'"


def connections(plan, rdp_password, private_key):
    """name -> (protocol, parameters). Attacker over RDP; each target a key-only SSH terminal."""
    user = plan["attacker"]["ssh_user"]
    out = {"attacker": ("rdp", {
        "hostname": plan["hosts"]["attacker"]["ip"], "port": "3389", "username": user, "password": rdp_password,
        "security": "any", "ignore-cert": "true", "resize-method": "display-update", "enable-wallpaper": "false"})}
    for t, v in plan["targets"].items():
        if "vm_id" in v:
            out[t] = ("ssh", {"hostname": plan["hosts"][t]["ip"], "port": "22", "username": plan["ops"]["ssh_user"],
                              "private-key": private_key, "color-scheme": "green-black"})
    return out


def connection_sql(conns):
    """Idempotent: each named connection is removed and recreated, then granted READ to the admin account."""
    sql = ["BEGIN;"]
    for name, (proto, params) in conns.items():
        sql.append("DELETE FROM guacamole_connection WHERE connection_name = %s AND parent_id IS NULL;" % lit(name))
        sql.append("INSERT INTO guacamole_connection (connection_name, protocol) VALUES (%s, %s);" % (lit(name), lit(proto)))
        for k, v in params.items():
            sql.append("INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) "
                       "SELECT connection_id, %s, %s FROM guacamole_connection WHERE connection_name = %s AND parent_id IS NULL;"
                       % (lit(k), lit(v), lit(name)))
        sql.append("INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission) "
                   "SELECT e.entity_id, c.connection_id, 'READ' FROM guacamole_entity e, guacamole_connection c "
                   "WHERE e.name = %s AND e.type = 'USER' AND c.connection_name = %s AND c.parent_id IS NULL;"
                   % (lit(ADMIN), lit(name)))
    sql.append("COMMIT;")
    return "\n".join(sql) + "\n"


def password_sql(password):
    digest, salt = password_hash(password)
    return ("UPDATE guacamole_user SET password_hash = decode(%s, 'hex'), password_salt = decode(%s, 'hex'), "
            "password_date = now() WHERE entity_id = (SELECT entity_id FROM guacamole_entity WHERE name = %s AND type = 'USER');\n"
            % (lit(digest.hex()), lit(salt.hex()), lit(ADMIN)))


def default_password_works(rows):
    """rows: 'hexhash|hexsalt' from the admin account. True when the stored hash is the default password's."""
    h, _, s = rows.strip().partition("|")
    return bool(h) and hashlib.sha256(DEFAULT_PASSWORD.encode() + s.upper().encode()).hexdigest() == h.lower()


def gateway_run(plan, sql):
    """Feed SQL to psql inside the gateway's compose project over SSH. GUACCTL_SSH overrides the ssh command (tests)."""
    gw = plan["gateway"]
    cmd = (os.environ.get("GUACCTL_SSH") or "ssh").split()
    remote = ("sudo docker-compose -f %s/compose.yml exec -T postgres psql -U guacamole -d guacamole "
              "-v ON_ERROR_STOP=1 -At" % gw["guacamole"]["dir"])
    r = subprocess.run(cmd + ["-o", "StrictHostKeyChecking=accept-new", "%s@%s" % (gw["ssh_user"], plan["hosts"]["gateway"]["ip"]), remote],
                       input=sql, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if r.returncode != 0:
        raise SystemExit("gateway SQL failed: " + r.stderr.strip()[-300:])
    return r.stdout


def need_env(name):
    v = os.environ.get(name, "")
    if not v:
        raise SystemExit("set " + name)
    return v


def admin_password():
    v = need_env("GUAC_ADMIN_PASSWORD")
    if len(v) < MIN_PASSWORD or v == DEFAULT_PASSWORD:
        raise SystemExit("GUAC_ADMIN_PASSWORD must be at least %d characters" % MIN_PASSWORD)
    return v


def do_connections(plan):
    rdp = need_env("ATTACKER_RDP_PASSWORD")
    if not os.path.exists(KEY_FILE):
        raise SystemExit("no %s: run playbooks/gateway.yml first" % os.path.relpath(KEY_FILE, ROOT))
    with open(KEY_FILE) as f:
        key = f.read()
    conns = connections(plan, rdp, key)
    gateway_run(plan, connection_sql(conns))
    print("connections: " + ", ".join(conns))


def web_login_status(plan, password):
    """(HTTP status, error type) of an API login without a TOTP code. A wrong password is also 403, but typed
    INVALID_CREDENTIALS; a demanded second factor is INSUFFICIENT_CREDENTIALS."""
    url = "https://%s:%d/api/tokens" % (plan["hosts"]["gateway"]["ip"], plan["gateway"]["web_port"])
    body = ("username=%s&password=%s" % (ADMIN, urllib.request.quote(password, safe=""))).encode()
    ctx = ssl._create_unverified_context()  # self-signed; the VPN is the trust boundary
    try:
        return urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=15, context=ctx).status, ""
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode()).get("type", "")
        except ValueError:
            return e.code, ""


def do_check(plan, say=print):
    bad = []
    rows = gateway_run(plan, "SELECT encode(password_hash,'hex') || '|' || encode(password_salt,'hex') FROM guacamole_user "
                             "WHERE entity_id = (SELECT entity_id FROM guacamole_entity WHERE name = %s AND type = 'USER');\n" % lit(ADMIN))
    if not rows.strip():
        bad.append("no guacadmin account")
    elif default_password_works(rows):
        bad.append("the default guacadmin password is still set")
    status, kind = web_login_status(plan, admin_password())
    if status == 200:
        bad.append("login succeeded without a TOTP code")
    elif (status, kind) != (403, "INSUFFICIENT_CREDENTIALS"):
        bad.append("expected a TOTP demand, got %s %s (wrong GUAC_ADMIN_PASSWORD?)" % (status, kind or "-"))
    say("\n".join(bad) or "ok: default password gone, TOTP demanded")
    return bad


def main(argv):
    plan = load_plan(os.environ.get("LAB_PLAN", DEFAULT_PLAN))
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "bootstrap":
        gateway_run(plan, password_sql(admin_password()))
        print("guacadmin password replaced")
        do_connections(plan)
    elif cmd == "connections":
        do_connections(plan)
    elif cmd == "check":
        return 1 if do_check(plan) else 0
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
