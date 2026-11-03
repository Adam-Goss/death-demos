"""#65: scripts must run in a checkout with no exec bits (synced from /mnt/c, unzipped on Windows).

`target.sh provision` called `scripts/lab.sh` directly, so a reset bumped the generation and then died with
`Permission denied` — the target left recorded at the new generation with the old VM. Two invariants keep that
class out: a script invoking another script in this repo goes through `bash`, and a file with a shebang carries
the exec bit in the git index.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# A script of this repo, however it is spelled: `scripts/x.sh`, `./scripts/x.sh`, `$ROOT/scripts/x.sh`.
# The lookbehind keeps `my-scripts/x.sh` out.
SCRIPT_PATH = re.compile(r"(?<![\w-])(?:[\w${}\"'.-]*/)?(scripts/[\w./-]+\.(?:sh|py))")
# Words that leave the next word in command position.
KEYWORDS = {"exec", "eval", "if", "while", "until", "then", "else", "elif", "do",
            "nohup", "time", "env", "command", "xargs", "sudo"}


def in_command_position(before):
    """Is a path starting here the command of a simple command, rather than an argument of one?

    Decided from the word in front of it: nothing, a separator (`;` `&&` `|` `$(` ...), a keyword that takes a
    command, or an environment assignment. An option (`test -f`), another path or an interpreter means argument.
    """
    before = before.rstrip()
    if not before:
        return True
    word = before.split()[-1]
    if word[-1] in ";&|(){`":
        return True
    if word in KEYWORDS:
        return True
    return bool(re.match(r"[A-Za-z_]\w*=", word)) and not re.search(r"[(`]", word)


def index_modes():
    """Path -> mode as the git index records it, or None when git cannot read this checkout."""
    r = subprocess.run(["git", "ls-files", "-s", "--", "scripts"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return {line.split("\t", 1)[1]: line.split()[0] for line in r.stdout.splitlines()}


def shell_scripts():
    skip = {".git", ".state", "__pycache__", "secrets"}
    return sorted(p for p in ROOT.rglob("*.sh") if not skip & set(p.relative_to(ROOT).parts))


def bare_invocations(text):
    """Lines of a shell script that run a repo script as a program instead of through `bash`/`sh`/`python3`.

    Heuristic, deliberately conservative: a match inside a quoted string (an odd number of unescaped quotes
    precedes it) is prose, not a call, and a path in argument position (`test -f scripts/lab.sh`) is not a call.
    Known blind spots, none of which the repo uses: a wrapper that takes its own arguments first
    (`timeout 30 scripts/lab.sh ...`), a path on a continued line, and a here-doc body.
    """
    bad = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for m in SCRIPT_PATH.finditer(line):
            before = line[:m.start()]
            if any(len(re.findall(r'(?<!\\)' + q, before)) % 2 for q in ('"', "'")):
                continue  # inside a string: a message, a cron line, a `bash -c` body
            if in_command_position(before):
                bad.append("%d: %s" % (n, line.strip()))
                break  # one report per line
    return bad


@unittest.skipIf(os.name == "nt", "POSIX exec bits do not exist on Windows; the Invariants below still run there")
class ProvisionInACheckoutWithoutExecBits(unittest.TestCase):
    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp()) / "checkout"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "network").mkdir()
        shutil.copy(ROOT / "network" / "plan.json", self.repo / "network" / "plan.json")
        shutil.copy(ROOT / "scripts" / "target.sh", self.repo / "scripts" / "target.sh")
        # The runner, as an unzipped-on-Windows checkout records it: readable, not executable.
        lab = self.repo / "scripts" / "lab.sh"
        lab.write_text('#!/usr/bin/env bash\necho "$@" > .state/lab-called\n')
        lab.chmod(0o644)
        (self.repo / "scripts" / "target.sh").chmod(0o644)

    def test_provision_reaches_the_tofu_runner(self):
        r = subprocess.run(["bash", "scripts/target.sh", "provision", "t1"],
                           cwd=self.repo, capture_output=True, text=True)
        called = self.repo / ".state" / "lab-called"
        self.assertTrue(called.exists(), "lab.sh was never run: %s" % r.stderr)
        self.assertEqual(called.read_text().strip(), "apply targets")
        self.assertNotIn("Permission denied", r.stderr)

    def test_labops_can_read_the_generation(self):
        """The first step of `labops.py reset`: it runs target.sh itself."""
        for name in ("labops.py", "labcommon.py", "elastic_api.py", "labpower.py", "pve.py"):
            shutil.copy(ROOT / "scripts" / name, self.repo / "scripts" / name)
        for p in (self.repo / "scripts").iterdir():
            p.chmod(0o644)
        r = subprocess.run([sys.executable, "scripts/labops.py", "generation", "t1"],
                           cwd=self.repo, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "1")


class Invariants(unittest.TestCase):
    def test_no_shell_script_runs_a_repo_script_as_a_program(self):
        offenders = {}
        for path in shell_scripts():
            bad = bare_invocations(path.read_text(encoding="utf-8"))
            if bad:
                offenders[path.relative_to(ROOT).as_posix()] = bad
        self.assertEqual(offenders, {},
                         "call these through `bash` (a checkout with no exec bits cannot run them): %s" % offenders)

    def test_a_script_with_a_shebang_is_executable_in_the_git_index(self):
        """What README and the runbooks tell an operator to type (`scripts/lab.sh apply ...`) must be runnable.

        Scoped to scripts/: those are the programs of this repo. The exec bit is lost in a checkout synced from
        /mnt/c or unzipped on Windows, which is why the callers above go through `bash` as well.
        """
        modes = index_modes()
        if modes is None:
            self.skipTest("git cannot read this checkout")
        wrong = {}
        for path, mode in modes.items():
            p = ROOT / path
            if not p.exists():
                continue
            shebang = p.read_bytes()[:2] == b"#!"
            if shebang and mode != "100755":
                wrong[path] = "has a shebang, recorded %s: git update-index --chmod=+x %s" % (mode, path)
            elif not shebang and mode == "100755":
                wrong[path] = "executable without a shebang: git update-index --chmod=-x %s" % path
        self.assertEqual(wrong, {}, wrong)


class Detector(unittest.TestCase):
    def test_a_bare_call_is_seen_however_it_is_spelled(self):
        for line in ("scripts/lab.sh apply targets",
                     "a && scripts/lab.sh plan x",
                     "exec scripts/a2-verify.sh home",
                     "FOO=1 scripts/lab.sh apply all",
                     "if scripts/lab.sh plan x; then echo y; fi",
                     "while scripts/lab.sh plan x; do sleep 1; done",
                     "$ROOT/scripts/lab.sh apply all",
                     '"$ROOT"/scripts/lab.sh apply all',
                     "./scripts/lab.sh apply all"):
            self.assertEqual(bare_invocations(line), ["1: " + line], line)

    def test_a_call_through_an_interpreter_or_a_mention_is_left_alone(self):
        for benign in ("bash scripts/lab.sh apply targets", "python3 scripts/netpolicy.py check",
                       "$PY scripts/labmode.py status", "sh scripts/install-deadman.sh /mnt",
                       "exec bash scripts/a2-verify.sh home", "test -f scripts/lab.sh",
                       "# run scripts/lab.sh apply all", 'echo "then run scripts/lab.sh apply all"',
                       'LAB=x bash "$ROOT/scripts/lab.sh" apply all',
                       "install -m 755 scripts/firewall/opaleye_deadman.py /usr/local/sbin/x",
                       "cp my-scripts/lab.sh /tmp"):
            self.assertEqual(bare_invocations(benign), [], benign)


if __name__ == "__main__":
    unittest.main()
