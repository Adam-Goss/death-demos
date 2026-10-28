"""Turn an exported OPNsense config.xml into the repo seed (issue #31).

    seed-sanitize.py exported.xml > seed/opnsense/config.xml.tmpl

Secrets become @@PLACEHOLDERS@@ (filled by seed-build.sh from the operator environment) and
the filter rules are dropped (labmode.py / netpolicy.py own them). `leaks()` is the guard
used by tests/static-checks.sh: it lists anything in a seed that still looks like a secret.
"""
import re
import sys
import xml.etree.ElementTree as ET

PLACEHOLDERS = {
    "ROOT_PASSWORD_HASH": "root account password hash",
    "API_KEY": "opaleye-api key",
    "API_SECRET_HASH": "opaleye-api secret (sha512-crypt)",
    "WG_PRIVATE_KEY": "WireGuard instance private key",
}
PLACEHOLDER = re.compile(r"@@([A-Z_]+)@@")
# Elements whose text is always secret, wherever they sit.
SECRET_TAGS = {"privkey", "psk", "pre-shared-key", "bcrypt-hash", "ipsecpsk", "authtoken"}


def _set(el, name):
    el.text = "@@%s@@" % name


def sanitize(root):
    """Mutates and returns root. Unknown secret-looking fields are blanked, not kept."""
    for sysel in root.iter("system"):
        for user in sysel.findall("user"):
            name = (user.findtext("name") or "").strip()
            pw = user.find("password")
            if name == "root":
                if pw is not None:
                    _set(pw, "ROOT_PASSWORD_HASH")
            else:
                # Only root and opaleye-api are expected; anything else is operator state.
                if pw is not None:
                    pw.text = ""
            for item in user.iter("item"):
                if item.find("key") is not None:
                    _set(item.find("key"), "API_KEY")
                    if item.find("secret") is not None:
                        _set(item.find("secret"), "API_SECRET_HASH")
    for el in root.iter():
        tag = el.tag.lower()
        if tag in SECRET_TAGS and (el.text or "").strip() and not PLACEHOLDER.fullmatch(el.text.strip()):
            _set(el, "WG_PRIVATE_KEY" if tag == "privkey" else "REMOVED_" + tag.upper().replace("-", "_"))
    # Filter rules: legacy section and the MVC ones labmode.py pushes.
    for filt in root.findall("filter"):
        for rule in filt.findall("rule"):
            filt.remove(rule)
    for rules in list(root.iter("rules")):
        if rules.find("rule") is not None:
            for r in rules.findall("rule"):
                rules.remove(r)
    return root


def leaks(text):
    """Strings that look like leftover secrets in a seed (placeholders are fine)."""
    found = []
    for m in re.finditer(r"<(privkey|psk|password|secret|key|bcrypt-hash)>([^<]+)</\1>", text):
        tag, val = m.group(1), m.group(2).strip()
        if val and not PLACEHOLDER.fullmatch(val):
            found.append("%s=%s..." % (tag, val[:6]))
    if re.search(r"\$[1256y]\$[./A-Za-z0-9$]{8,}", text):
        found.append("crypt hash")
    if "<rule>" in text and "<filter" in text:
        found.append("filter rules")
    return found


def main(argv):
    tree = ET.parse(argv[1])
    sanitize(tree.getroot())
    ET.indent(tree)
    out = ET.tostring(tree.getroot(), encoding="unicode")
    bad = leaks(out)
    if bad:
        sys.exit("refusing: seed still holds %s" % ", ".join(bad))
    print(out)


if __name__ == "__main__":
    main(sys.argv)
