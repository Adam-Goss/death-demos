import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import importlib

seed = importlib.import_module("seed-sanitize")

SAMPLE = """<opnsense><system>
<user><name>root</name><password>$6$abcdefgh$verylonghashvalue</password></user>
<user><name>opaleye-api</name><password>$6$zzzzzzzz$otherhashvalue</password>
<apikeys><item><key>AKEYAKEYAKEY</key><secret>$6$kkkkkkkk$secrethashvalue</secret></item></apikeys></user>
</system>
<filter><rule><type>pass</type></rule></filter>
<OPNsense><wireguard><server><servers><server><privkey>SUPERSECRETPRIVATEKEY=</privkey></server></servers></server>
<client><clients><client><psk>PRESHAREDPRESHARED=</psk><pubkey>PUBLICKEY=</pubkey></client></clients></client></wireguard></OPNsense>
</opnsense>"""


class SeedTest(unittest.TestCase):
    def run_sanitize(self):
        root = seed.sanitize(ET.fromstring(SAMPLE))
        return ET.tostring(root, encoding="unicode")

    def test_secrets_become_placeholders(self):
        out = self.run_sanitize()
        for s in ("abcdefgh", "AKEYAKEYAKEY", "SUPERSECRET", "PRESHARED", "kkkkkkkk", "zzzzzzzz"):
            self.assertNotIn(s, out)
        for p in ("ROOT_PASSWORD_HASH", "API_KEY", "API_SECRET_HASH", "WG_PRIVATE_KEY"):
            self.assertIn("@@%s@@" % p, out)
        self.assertIn("PUBLICKEY=", out)

    def test_filter_rules_dropped(self):
        self.assertNotIn("<rule>", self.run_sanitize())

    def test_sanitized_output_has_no_leaks(self):
        self.assertEqual(seed.leaks(self.run_sanitize()), [])

    def test_leaks_catches_raw_export(self):
        self.assertTrue(seed.leaks(SAMPLE))


if __name__ == "__main__":
    unittest.main()
