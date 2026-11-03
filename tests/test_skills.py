"""Offline guards for the project's Claude Code skills (#60).

A skill is a procedure an agent follows against the live lab, so the failure to guard against is drift:
a skill naming a command, flag or document this repo does not have. Everything here is read from the
skill files themselves, so a new skill is covered the moment it is added.
"""
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SKILLS = os.path.join(ROOT, ".claude", "skills")
# The eight of #60's acceptance list: its seven, plus lab-workstation-setup (#61), which it adopted.
REQUIRED = ("lab-deploy", "lab-teardown", "lab-status", "lab-troubleshoot", "lab-maintenance",
            "lab-exercise-run", "lab-malware-analysis", "lab-workstation-setup")


def skill_names():
    return sorted(d for d in os.listdir(SKILLS) if os.path.isdir(os.path.join(SKILLS, d)))


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def skill_text(name):
    return read(os.path.join(".claude", "skills", name, "SKILL.md"))


def frontmatter(text):
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    if not m:
        return {}
    out = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


class Contract(unittest.TestCase):
    """Every skill is a SKILL.md with the frontmatter Claude Code needs, and the seven of #60 are there."""

    def test_the_skills_of_issue_60_exist(self):
        self.assertEqual([], [n for n in REQUIRED if n not in skill_names()])

    def test_each_skill_directory_holds_a_skill_md(self):
        for name in skill_names():
            with self.subTest(name):
                self.assertTrue(os.path.isfile(os.path.join(SKILLS, name, "SKILL.md")))

    def test_frontmatter_name_matches_the_directory(self):
        for name in skill_names():
            with self.subTest(name):
                self.assertEqual(name, frontmatter(skill_text(name)).get("name"))

    def test_description_is_a_trigger_not_a_title(self):
        # The description is all the agent sees when deciding whether a skill applies: a few words are not enough.
        for name in skill_names():
            with self.subTest(name):
                self.assertGreaterEqual(len(frontmatter(skill_text(name)).get("description", "")), 40)

    def test_skills_are_user_invoked_only(self):
        # These skills power, destroy and rebuild a real lab: they are never model-invoked on a guess.
        for name in skill_names():
            with self.subTest(name):
                self.assertEqual("true", frontmatter(skill_text(name)).get("disable-model-invocation"))


class CitedPaths(unittest.TestCase):
    """A skill that names a file this repo does not have sends the agent somewhere else."""

    def test_every_repo_path_a_skill_names_exists(self):
        # Paths as they are written in prose and commands: scripts/x, ansible/playbooks/x.yml, network/plan.json, tests/x.
        pattern = re.compile(r"\b((?:scripts|network|tests)/[\w./-]*[\w]|playbooks/[\w.-]+\.yml)")
        for name in skill_names():
            for path in sorted(set(pattern.findall(skill_text(name)))):
                rel = os.path.join("ansible", path) if path.startswith("playbooks/") else path
                with self.subTest(skill=name, path=path):
                    self.assertTrue(os.path.exists(os.path.join(ROOT, rel)), rel)

    def test_every_markdown_link_resolves(self):
        # Relative links out of .claude/skills/<name>/ to the README, runbooks and ADRs.
        for name in skill_names():
            base = os.path.join(SKILLS, name)
            for target in re.findall(r"\]\((\.\./[^)#]+)", skill_text(name)):
                with self.subTest(skill=name, link=target):
                    self.assertTrue(os.path.exists(os.path.join(base, target)), target)

    def test_each_skill_cites_the_document_it_is_based_on(self):
        # Acceptance criterion of #60: no duplicated procedure drift, so every skill points at its source.
        for name in skill_names():
            with self.subTest(name):
                self.assertRegex(skill_text(name), r"README\.md|docs/runbooks/|docs/adr/|runbooks/")


def code_spans(text):
    """Commands only: fenced blocks and inline-code spans. Prose mentioning a script is not an invocation."""
    spans = re.findall(r"```[a-z]*\n(.*?)```", text, re.S) + re.findall(r"`([^`\n]+)`", text)
    return "\n".join(spans)


def help_choices(args):
    """The subcommand names argparse prints as {a,b,c}; building the parser needs no lab and no env."""
    r = subprocess.run([sys.executable] + args, cwd=ROOT, capture_output=True, text=True)
    m = re.search(r"\{([a-z0-9][a-z0-9,._-]+)\}", r.stdout + r.stderr)
    return set(m.group(1).split(",")) if m else set()


def case_branches(rel):
    """The commands a shell script accepts, read from its `case` branches."""
    text, out = read(rel), set()
    for m in re.finditer(r"^\s{0,6}([a-z][a-z|-]*)\)", text, re.M):
        out |= set(m.group(1).split("|"))
    for m in re.finditer(r"case \$\w+ in ([a-z|]+)\)", text):
        out |= set(m.group(1).split("|"))
    return out


def doc_commands(rel, prog):
    """The commands a docstring-documented script lists as `prog <command>`."""
    doc = read(rel).split('"""')[1] if '"""' in read(rel) else ""
    return set(re.findall(re.escape(prog) + r" ([a-z][a-z-]+)", doc))


COMMANDS = {
    "labops.py": lambda: help_choices(["scripts/labops.py", "--help"]),
    "labmode.py": lambda: help_choices(["scripts/labmode.py", "--help"]),
    "fleetctl.py": lambda: help_choices(["scripts/fleetctl.py", "--help"]),
    "netpolicy.py": lambda: doc_commands("scripts/netpolicy.py", "netpolicy.py"),
    "guacctl.py": lambda: doc_commands("scripts/guacctl.py", "guacctl.py"),
    "lab.sh": lambda: case_branches("scripts/lab.sh"),
    "target.sh": lambda: case_branches("scripts/target.sh"),
    "ops-timers.sh": lambda: case_branches("scripts/ops-timers.sh"),
}
# A command whose first word opens a second level of subcommands.
NESTED = {("labops.py", "exercise"): ["scripts/labops.py", "exercise", "--help"],
          ("labops.py", "analysis-sample"): ["scripts/labops.py", "analysis-sample", "--help"]}


class NamedCommands(unittest.TestCase):
    """The acceptance criterion of #60: a skill calls only commands this repo actually has."""

    def test_the_command_tables_are_not_empty(self):
        # Guard against a silently vacuous check if a script's CLI stops being readable this way.
        for tool, lookup in COMMANDS.items():
            with self.subTest(tool):
                self.assertTrue(lookup(), tool)

    def test_every_subcommand_a_skill_names_exists(self):
        known = {tool: lookup() for tool, lookup in COMMANDS.items()}
        # Same line only: spans are joined by newlines, and a mention in one span does not command the next.
        pattern = re.compile(r"\b(%s)[ \t]+([a-z][\w.-]*)(?:[ \t]+([a-z][\w.-]*))?"
                             % "|".join(re.escape(t) for t in COMMANDS))
        for name in skill_names():
            for tool, first, second in pattern.findall(code_spans(skill_text(name))):
                with self.subTest(skill=name, command="%s %s" % (tool, first)):
                    self.assertIn(first, known[tool])
                if second and (tool, first) in NESTED:
                    with self.subTest(skill=name, command="%s %s %s" % (tool, first, second)):
                        self.assertIn(second, help_choices(NESTED[(tool, first)]))

    def test_every_flag_a_skill_names_exists(self):
        """A flag is as easy to invent as a command, and `--acknowledge-loss` is the dangerous one."""
        flags = {tool: set(re.findall(r"--[a-z][a-z-]+", read("scripts/" + tool))) for tool in COMMANDS}
        for name in skill_names():
            for line in code_spans(skill_text(name)).splitlines():
                tools = [t for t in COMMANDS if t in line]
                if len(tools) != 1:  # ambiguous or none: attribute nothing
                    continue
                for flag in re.findall(r"--[a-z][a-z-]+", line):
                    with self.subTest(skill=name, command="%s %s" % (tools[0], flag)):
                        self.assertIn(flag, flags[tools[0]])


class Discoverable(unittest.TestCase):
    """A skill nobody is told about does not get used: the usage guide names every one of them."""

    def test_the_readme_links_every_skill(self):
        readme = read("README.md")
        missing = [n for n in skill_names() if ".claude/skills/%s/SKILL.md" % n not in readme]
        self.assertEqual([], missing)


if __name__ == "__main__":
    unittest.main()
