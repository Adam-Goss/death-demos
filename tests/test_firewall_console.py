import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import firewall_console  # noqa: E402


class FakeLink:
    """Scripted serial link: each write unlocks the next chunk of output."""

    def __init__(self, banner, replies):
        self.pending = banner
        self.replies = list(replies)
        self.sent = []

    def read(self, n):
        out, self.pending = self.pending[:n], self.pending[n:]
        return out

    def write(self, data):
        self.sent.append(data)
        if self.replies:
            self.pending += self.replies.pop(0)


MENU = b"boot noise\r\nEnter an option: "
SHELL = b"8\r\n# "
IMPORTED = b"importer chatter\r\nIMPORT-OK-42\r\n# "
VERIFIED = b"CONFIG-OK-42\r\n# "


class ImportSeed(unittest.TestCase):
    def test_drives_menu_shell_then_importer(self):
        link = FakeLink(MENU, [b"", SHELL, IMPORTED, VERIFIED, b"halting\r\n"])
        firewall_console.import_seed(link, device="cd0", timeout=1)
        self.assertEqual(link.sent, [
            b"\n", b"8\n", b"opnsense-importer cd0 && echo IMPORT-OK-$((6*7))\n",
            b"grep -q opaleye-api /conf/config.xml && echo CONFIG-OK-$((6*7))\n", b"poweroff\n"])

    def test_logs_in_first_when_the_nano_image_shows_a_login_prompt(self):
        banner = b"FreeBSD/amd64 (OPNsense.internal) (ttyu0)\r\n\r\nlogin: "
        link = FakeLink(banner, [b"", b"Password:", MENU, SHELL, IMPORTED, VERIFIED, b"halting\r\n"])
        firewall_console.import_seed(link, device="cd0", timeout=1)
        self.assertEqual(link.sent[:5], [b"\n", b"root\n", b"opnsense\n", b"8\n",
                                         b"opnsense-importer cd0 && echo IMPORT-OK-$((6*7))\n"])

    def test_importer_failure_is_an_error_not_a_hang(self):
        link = FakeLink(MENU, [b"", SHELL, b"No config found on cd0\r\n# "])
        with self.assertRaises(firewall_console.ConsoleError):
            firewall_console.import_seed(link, device="cd0", timeout=0.2)
        self.assertNotIn(b"poweroff\n", link.sent)

    def test_missing_menu_times_out(self):
        link = FakeLink(b"still booting", [])
        with self.assertRaises(firewall_console.ConsoleError):
            firewall_console.import_seed(link, device="cd0", timeout=0.2)
        self.assertEqual(link.sent, [b"\n"])


if __name__ == "__main__":
    unittest.main()
