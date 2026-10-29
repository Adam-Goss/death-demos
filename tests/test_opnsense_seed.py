import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import labmode  # noqa: E402
import opnsense_seed as seed  # noqa: E402

WG = "A" * 43 + "="
ENV = {
    "OPNSENSE_ROOT_PASSWORD": "correct-horse-battery",
    "OPNSENSE_API_KEY": "k" * 40,
    "OPNSENSE_API_SECRET": "s" * 40,
    "OPNSENSE_WG_PRIVATE_KEY": "B" + "A" * 42 + "=",
    "OPNSENSE_WG_PUBLIC_KEY": "C" + "A" * 42 + "=",
    "OPNSENSE_WG_PEER_PUBLIC_KEY": "D" + "A" * 42 + "=",
}


def seed_text():
    with open(seed.SEED) as f:
        return f.read()


class SeedTest(unittest.TestCase):
    def setUp(self):
        self.plan = seed.load_plan()
        self.tpl = seed.template(self.plan)
        self.root = ET.fromstring(self.tpl)

    def test_committed_seed_matches_generator(self):
        self.assertEqual(seed_text(), self.tpl)

    def test_template_has_no_secrets_and_passes_invariants(self):
        self.assertFalse(seed.looks_secret(self.tpl))
        self.assertEqual(seed.problems(self.tpl), [])

    def test_interfaces_follow_plan(self):
        for i, z in enumerate(self.plan["nic_order"]):
            e = self.root.find("interfaces/" + self.plan["zones"][z]["iface"])
            self.assertEqual(e.findtext("if"), "vtnet%d" % i)
        lan = self.root.find("interfaces/lan")
        self.assertEqual(lan.findtext("ipaddr"), "10.77.1.1")
        self.assertEqual(lan.findtext("subnet"), "24")
        self.assertEqual(self.root.findtext("interfaces/wan/ipaddr"), self.plan["firewall"]["wan_ip"])
        self.assertEqual(self.root.findtext("interfaces/opt4/if"), "wg0")

    def test_dns_ntp_on_lab_interfaces_only(self):
        want = "lan,opt1,opt2,opt3"
        self.assertEqual(self.root.findtext("OPNsense/unboundplus/general/active_interface"), want)
        self.assertEqual(self.root.findtext("ntpd/interface"), want)

    def test_wireguard_is_v4_only_and_matches_plan(self):
        s = self.root.find("OPNsense/wireguard/server/servers/server")
        self.assertEqual(s.findtext("port"), "51820")
        self.assertEqual(s.findtext("tunneladdress"), "10.77.9.1/24")
        c = self.root.find("OPNsense/wireguard/client/clients/client")
        self.assertEqual(c.findtext("tunneladdress"), "10.77.9.2/32")
        self.assertEqual(s.findtext("peers"), c.get("uuid"))

    def rules(self):
        return {r.findtext("description"): {c.tag: c.text or "" for c in r}
                for r in self.root.iterfind("OPNsense/Firewall/Filter/rules/rule")}

    def test_bootstrap_rules_are_labmodes_own_payloads(self):
        want = labmode.desired(self.plan, "exercise", None)
        got = self.rules()
        self.assertEqual({"opaleye:vpn-handshake@wan@workstation:51820", "opaleye:op-fw-admin@opt4@vpn:443",
                          "opaleye:v6-block@wan", "opaleye:deny-all@wan",
                          "opaleye:v6-block@opt4", "opaleye:deny-all@opt4"}, set(got))
        for d, payload in got.items():
            self.assertEqual(payload, want[d], d)  # labmode's first sync finds nothing to change
        self.assertEqual(got["opaleye:vpn-handshake@wan@workstation:51820"]["enabled"], "1")

    def test_nothing_beyond_bootstrap_is_open(self):
        self.assertIsNone(self.root.find("filter"))
        for d, p in self.rules().items():
            if p["action"] == "pass":
                self.assertTrue(d.startswith(("opaleye:vpn-handshake", "opaleye:op-fw-admin")), d)

    def test_generation_is_deterministic(self):
        self.assertEqual(seed.template(self.plan), seed.template(self.plan))

    def test_root_is_in_the_admins_group(self):
        # without the group root has no GUI privileges and login is refused
        g = self.root.find("system/group[name='admins']")
        self.assertEqual(g.findtext("priv"), "page-all")
        self.assertEqual(g.findtext("member"), "0")

    def test_render_injects_hashed_secrets(self):
        out = seed.render(ENV, self.plan)
        self.assertNotIn("@@", out)
        self.assertNotIn(ENV["OPNSENSE_ROOT_PASSWORD"], out)
        self.assertNotIn(ENV["OPNSENSE_API_SECRET"], out)
        r = ET.fromstring(out)
        self.assertTrue(r.findtext("system/user/password").startswith("$2y$"))
        key, secret = r.find("system/user[2]/apikeys").text.split("|")
        self.assertEqual(key, ENV["OPNSENSE_API_KEY"])
        self.assertTrue(secret.startswith("$6$"))
        self.assertEqual(r.findtext("OPNsense/wireguard/server/servers/server/privkey"), ENV["OPNSENSE_WG_PRIVATE_KEY"])
        self.assertTrue(seed.looks_secret(out))
        self.assertEqual(seed.problems(out), [])

    def test_render_rejects_missing_and_malformed(self):
        for name in ENV:
            env = dict(ENV)
            del env[name]
            with self.assertRaises(SystemExit):
                seed.render(env, self.plan)
        for name, bad in (("OPNSENSE_WG_PRIVATE_KEY", "short"), ("OPNSENSE_ROOT_PASSWORD", "tiny"),
                          ("OPNSENSE_API_KEY", "x")):
            with self.assertRaises(SystemExit):
                seed.render(dict(ENV, **{name: bad}), self.plan)

    def test_invariants_catch_regressions(self):
        cases = {
            "legacy": ("</opnsense>", "<filter/></opnsense>"),
            "extra": ("op-fw-admin@opt4@vpn:443", "op-attacker-ssh@opt4@vpn:22"),
            "blockpriv": ("<enable>1</enable>", "<enable>1</enable><blockpriv>1</blockpriv>"),
            "page-all": ("page-filter-api", "page-all"),
            "ipv6": ("<system>", "<system><ipv6allow>1</ipv6allow>"),
            "antilockout": ("<noantilockout>1</noantilockout>", ""),
        }
        for label, (old, new) in cases.items():
            self.assertTrue(seed.problems(self.tpl.replace(old, new, 1)), label)

    def test_render_file_is_owner_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.xml")
            seed.write_private(p, "x")
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
