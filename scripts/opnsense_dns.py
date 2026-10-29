#!/usr/bin/env python3
"""Converge an existing M2 firewall to the seed's local-only system DNS.

Usage: opnsense_dns.py [--apply]. Uses OPNSENSE_URL/ROOT_PASSWORD for the
legacy General Settings form, and the normal API credentials for dead-man
markers. Does not expand the scoped API user's privileges. Run in exercise
mode with no target selected; Unbound must already run without forwarding.
"""
import argparse
import html.parser
import http.cookiejar
import json
import os
import re
import ssl
import urllib.parse
import urllib.request
import uuid

import labmode


class Form(html.parser.HTMLParser):
    """Preserve successful form controls, including selects and checked boxes."""
    def __init__(self, page):
        super().__init__()
        self.fields, self.select = {}, None
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "input" and a.get("name"):
            if a.get("type") in ("checkbox", "radio") and "checked" not in a:
                return
            if a.get("type") not in ("file", "button"):
                self.fields[a["name"]] = a.get("value", "")
        elif tag == "select" and a.get("name"):
            self.select = (a["name"], "multiple" in a, [], [])
        elif tag == "option" and self.select:
            self.select[2].append(a.get("value", ""))
            if "selected" in a:
                self.select[3].append(a.get("value", ""))

    def handle_endtag(self, tag):
        if tag == "select" and self.select:
            name, multiple, options, selected = self.select
            values = selected or ([] if multiple else options[:1])
            self.fields[name] = values if multiple else (values[0] if values else "")
            self.select = None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    lab = labmode.Lab()
    if (lab.st["mode"], lab.st["selected"]) != ("exercise", None):
        raise SystemExit("requires exercise mode with no target selected")
    base = os.environ["OPNSENSE_URL"].rstrip("/")
    password = os.environ["OPNSENSE_ROOT_PASSWORD"]
    ctx = ssl._create_unverified_context() if os.environ.get("OPNSENSE_INSECURE") == "true" else ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                        urllib.request.HTTPSHandler(context=ctx))

    def get(path):
        with opener.open(base + path, timeout=30) as response:
            return response.read().decode()

    def post(path, fields, headers=None):
        data = json.dumps(fields).encode() if headers else urllib.parse.urlencode(fields, doseq=True).encode()
        req = urllib.request.Request(base + path, data, headers=headers or {})
        with opener.open(req, timeout=60) as response:
            return response.read().decode()

    login = Form(get("/")).fields
    login.update(usernamefld="root", passwordfld=password, login="1")
    post("/", login)
    general = Form(get("/system_general.php")).fields
    if general.get("hostname") != "opaleye-firewall":
        raise SystemExit("login failed or this is not the lab firewall")
    ui = get("/ui/unbound/general")
    token = re.search(r'"X-CSRFToken",\s*"([^"]+)"', ui).group(1)
    headers = {"Content-Type": "application/json", "X-CSRFToken": token}
    settings = json.loads(get("/api/unbound/settings/get"))["unbound"]
    if settings["general"]["enabled"] != "1" or settings["forwarding"]["enabled"] != "0":
        raise SystemExit("requires enabled recursive Unbound; system-server forwarding would create a DNS loop")
    want = {"dns1": "127.0.0.1", **{"dns%d" % n: "" for n in range(2, 9)}}

    def matches(fields):
        return all(fields.get(k, "") == v for k, v in want.items()) and not any(fields.get(k) for k in ("dnsallowoverride", "dnslocalhost"))

    cache_matches = settings["advanced"]["cacheminttl"] == "600"
    if matches(general) and cache_matches:
        print("system DNS already uses only local Unbound: no changes")
        return
    if not args.apply:
        raise SystemExit("system DNS differs from the seed; run with --apply")
    client = lab.client()
    pending, confirmed = client.marker(labmode.PENDING), client.marker(labmode.CONFIRMED)
    if pending is None or confirmed is None or pending != confirmed:
        raise SystemExit("dead-man switch must be armed with no unconfirmed push")
    marker = uuid.uuid4().hex
    client.set_marker(labmode.PENDING, marker)
    if not matches(general):
        general.update(want)
        general.pop("dnsallowoverride", None)
        general.pop("dnslocalhost", None)
        for n in range(1, 9):
            general["dns%dgw" % n] = "none"
        post("/system_general.php", general)
    if not matches(Form(get("/system_general.php")).fields):
        raise SystemExit("DNS change did not persist; push left unconfirmed")
    if not cache_matches:
        result = json.loads(post("/api/unbound/settings/set", {"unbound": {"advanced": {"cacheminttl": "600"}}}, headers))
        if result.get("result") != "saved":
            raise SystemExit("Unbound cache setting rejected; push left unconfirmed")
        result = json.loads(post("/api/unbound/service/reconfigure", {}, headers))
        if result.get("status") != "ok":
            raise SystemExit("Unbound reconfigure failed; push left unconfirmed")
    if json.loads(get("/api/unbound/settings/get"))["unbound"]["advanced"]["cacheminttl"] != "600":
        raise SystemExit("Unbound cache setting did not persist; push left unconfirmed")
    # General Settings reloads DNS and the filter; refresh alias tables too.
    result = json.loads(post("/api/firewall/alias/reconfigure", {}, headers))
    if result.get("status") != "ok":
        raise SystemExit("alias refresh failed; push left unconfirmed")
    client.set_marker(labmode.CONFIRMED, marker)
    lab.commit("system-dns-local")
    print("system DNS now uses only local Unbound; alias refresh requested and admin path confirmed")


if __name__ == "__main__":
    main()
