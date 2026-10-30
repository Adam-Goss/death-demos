"""Offline guards for the Guacamole gateway (#51): provisioning SQL, the default-password check, plan wiring."""
import hashlib
import json
import os
import re
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import guacctl  # noqa: E402

PLAN = guacctl.load_plan()


def read(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


class Connections(unittest.TestCase):
    def setUp(self):
        self.c = guacctl.connections(PLAN, "rdp-pw", "KEY")

    def test_attacker_is_rdp_and_each_target_vm_is_ssh_at_plan_addresses(self):
        self.assertEqual(set(self.c), {"attacker", "t1"})  # t2 has no VM yet
        self.assertEqual(self.c["attacker"][0], "rdp")
        self.assertEqual(self.c["attacker"][1]["hostname"], PLAN["hosts"]["attacker"]["ip"])
        self.assertEqual(self.c["attacker"][1]["port"], "3389")
        self.assertEqual(self.c["t1"][0], "ssh")
        self.assertEqual((self.c["t1"][1]["hostname"], self.c["t1"][1]["port"]), (PLAN["hosts"]["t1"]["ip"], "22"))

    def test_targets_are_key_only_and_get_no_desktop(self):
        self.assertIn("private-key", self.c["t1"][1])
        self.assertNotIn("password", self.c["t1"][1])
        self.assertTrue(all(p != "rdp" for n, (p, _) in self.c.items() if n != "attacker"))

    def test_only_firewall_allowed_destinations_are_brokered(self):
        import netpolicy
        rules = netpolicy.render_rules(PLAN, "exercise", None)
        for name, (proto, params) in self.c.items():
            port = int(params["port"])
            self.assertEqual(netpolicy.evaluate(PLAN, rules, {"src": "gateway", "dst": name, "proto": "tcp", "port": port}),
                             "allow", name)

    def test_sql_is_idempotent_transactional_and_quotes_values(self):
        sql = guacctl.connection_sql(guacctl.connections(PLAN, "o'neil", "K"))
        self.assertTrue(sql.startswith("BEGIN;") and sql.rstrip().endswith("COMMIT;"))
        self.assertIn("DELETE FROM guacamole_connection WHERE connection_name = 'attacker'", sql)
        self.assertIn("'o''neil'", sql)
        self.assertEqual(sql.count("INSERT INTO guacamole_connection (connection_name"), 2)

    def test_nul_is_refused(self):
        with self.assertRaises(ValueError):
            guacctl.lit("a\x00b")


class Passwords(unittest.TestCase):
    def test_hash_matches_guacamoles_sha256_with_hex_salt(self):
        digest, salt = guacctl.password_hash("pw", b"\x01\x02")
        self.assertEqual(digest, hashlib.sha256(b"pw0102").digest())
        self.assertEqual(len(guacctl.password_hash("pw")[1]), 32)

    def test_default_password_is_detected_from_the_stored_row(self):
        digest, salt = guacctl.password_hash("guacadmin")
        self.assertTrue(guacctl.default_password_works("%s|%s\n" % (digest.hex(), salt.hex())))
        digest, salt = guacctl.password_hash("a-long-replacement-pw")
        self.assertFalse(guacctl.default_password_works("%s|%s\n" % (digest.hex(), salt.hex())))
        self.assertFalse(guacctl.default_password_works(""))

    def test_password_sql_never_contains_the_password(self):
        self.assertNotIn("replacement-secret-pw", guacctl.password_sql("replacement-secret-pw"))

    def test_short_or_default_admin_password_is_refused(self):
        for v in ("short", "guacadmin"):
            os.environ["GUAC_ADMIN_PASSWORD"] = v
            with self.assertRaises(SystemExit):
                guacctl.admin_password()
        os.environ.pop("GUAC_ADMIN_PASSWORD")


class PlanWiring(unittest.TestCase):
    def test_gateway_stack_reads_plan_and_stays_off_the_home_bridge(self):
        tf = read("tofu/stacks/gateway/main.tf") + read("tofu/stacks/gateway/versions.tf")
        self.assertIn('zones["gateway"]', tf)
        self.assertIn("local.zone.bridge", tf)
        self.assertNotRegex(tf, r"vmbr\d+")
        self.assertNotRegex(tf, r"zones\.home|zones\[\"home\"\]")
        self.assertNotRegex(tf, r"(?m)^\s*ssh\s*\{")
        self.assertIn("gateway.tfstate", tf)
        self.assertIn('"iso-files"', tf)  # disk on iso-files, never local

    def test_gateway_has_its_own_pool_token_and_runner_slot(self):
        self.assertIn("gateway", re.search(r"for stack in ([a-z ]+);", read("scripts/bootstrap-proxmox.sh")).group(1))
        self.assertEqual(PLAN["gateway"]["pool"], "lab-gateway")
        self.assertIn('default     = "lab-gateway"', read("tofu/stacks/gateway/main.tf"))
        self.assertIn("gateway", re.search(r'ORDER="([a-z ]+)"', read("scripts/lab.sh")).group(1))

    def test_images_are_pinned_by_digest(self):
        for name, i in PLAN["gateway"]["guacamole"]["images"].items():
            self.assertRegex(i["digest"], r"^sha256:[0-9a-f]{64}$", name)

    def test_compose_publishes_only_the_proxy_and_enables_totp(self):
        y = read("ansible/roles/gateway/templates/compose.yml.j2")
        self.assertEqual(y.count("ports:"), 1)
        self.assertIn("TOTP_ENABLED=true", y)
        self.assertNotIn("guacadmin", y)

    def test_no_secret_literals_in_the_role(self):
        text = "".join(read("ansible/roles/gateway/" + p) for p in ("tasks/main.yml", "defaults/main.yml", "templates/compose.yml.j2"))
        self.assertNotRegex(text, r"(?i)password: *[\"'][A-Za-z0-9]{8,}")

    def test_attacker_desktop_exists_and_attacker_is_not_enrolled_in_fleet(self):
        self.assertIn("xorgxrdp", read("ansible/roles/attacker/defaults/main.yml"))  # install_recommends is off: Xorg comes only from this
        self.assertNotIn("attacker", read("scripts/fleetctl.py").lower().replace("attacker-side", ""))
        self.assertNotRegex(read("ansible/roles/attacker/tasks/main.yml"), r"(?i)elastic-agent|fleet")

    def test_gateway_is_an_update_initiator_and_a_vm_the_audit_covers(self):
        self.assertIn("gateway", PLAN["maintenance"]["initiators"])
        import nicaudit
        self.assertEqual(nicaudit.POOLS["gateway"], "lab-gateway")


if __name__ == "__main__":
    unittest.main()
