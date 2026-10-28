"""Operator commands (issue #24): exercise markers, drain check, target reset, lab shutdown/startup.

Run as the operator runs them (CLI), against fake Elasticsearch/Proxmox and stub ssh/lab.sh/ansible.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
from fake_elastic import FakeEs  # noqa: E402
from fake_pve import FakePve  # noqa: E402

PLAN = json.load(open(os.path.join(ROOT, "network/plan.json")))
FW, EL, AT = PLAN["firewall"]["vm_id"], PLAN["elastic"]["vm_id"], PLAN["attacker"]["vm_id"]
T1, T2 = PLAN["targets"]["t1"]["vm_id"], PLAN["targets"]["t2"]["vm_id"]


class OpsCase(unittest.TestCase):
    def setUp(self):
        self.es = FakeEs()
        self.pve = FakePve({FW: "running", EL: "running", AT: "running", T1: "running", T2: "running"})
        self.dir = tempfile.mkdtemp()
        self.state = os.path.join(self.dir, "state")
        os.makedirs(self.state)
        self.log = os.path.join(self.dir, "stub.log")
        open(self.log, "w").close()
        pw = os.path.join(self.dir, "pw")
        with open(pw, "w") as f:
            f.write("pw\n")
        self.env = dict(
            os.environ, LABMODE_STATE_DIR=self.state, LABOPS_SSH=os.path.join(HERE, "stub_ssh.py"),
            LABOPS_LAB_SH=os.path.join(HERE, "stub_cmd.sh"), LABOPS_ANSIBLE=os.path.join(HERE, "stub_cmd.sh"),
            LABOPS_POLL="0.05", LABOPS_DRAIN_TIMEOUT="1", STUB_LOG=self.log, FAKE_ES_URL=self.es.url,
            ELASTIC_ES_URL=self.es.url, ELASTIC_KB_URL=self.es.url, ELASTIC_PASSWORD_FILE=pw,
            PROXMOX_VE_ENDPOINT=self.pve.url, PVE_NODE="n1",
            PROXMOX_VE_API_TOKEN_FIREWALL="fw!t=1", PROXMOX_VE_API_TOKEN_ELASTIC="el!t=2",
            PROXMOX_VE_API_TOKEN_TARGETS="tg!t=3", PROXMOX_VE_API_TOKEN_ATTACKER="at!t=4")
        self.labmode("exercise", "t1")

    def tearDown(self):
        self.es.close()
        self.pve.close()

    def labmode(self, mode, selected):
        with open(os.path.join(self.state, "labmode.json"), "w") as f:
            json.dump({"mode": mode, "selected": selected, "expires": None, "reverify_required": False}, f)

    def ops(self, *args, **env):
        return subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "labops.py"), *args],
                              env=dict(self.env, **env), capture_output=True, text=True)

    def stub_calls(self):
        with open(self.log) as f:
            return [line.rstrip("\n") for line in f if line.strip()]

    def markers(self):
        return self.es.docs.get(PLAN["ops"]["marker_stream"], [])

    def audit(self):
        with open(os.path.join(self.state, "labops.log")) as f:
            return [json.loads(line) for line in f]

    def start(self, ex="ex-001", target="t1"):
        r = self.ops("exercise", "start", ex, "--target", target)
        self.assertEqual(r.returncode, 0, r.stderr)


class ExerciseMarkers(OpsCase):
    def test_start_writes_a_marker_with_the_lab_fields(self):
        self.start()
        (m,) = self.markers()
        self.assertEqual(m["lab"], {"exercise_id": "ex-001", "target_id": "t1", "rebuild_generation": 1})
        self.assertEqual(m["event"]["action"], "exercise-start")
        self.assertEqual(m["event"]["dataset"], "lab_marker.events")
        self.assertIn("@timestamp", m)

    def test_start_refuses_a_bad_id(self):
        for bad in ("A b", "x", "../etc", "ex 1", "a" * 70):
            r = self.ops("exercise", "start", bad, "--target", "t1")
            self.assertNotEqual(r.returncode, 0, bad)
        self.assertEqual(self.markers(), [])

    def test_start_refuses_unless_the_firewall_is_in_exercise_mode_with_that_target(self):
        self.labmode("maintenance", None)
        self.assertNotEqual(self.ops("exercise", "start", "ex-1", "--target", "t1").returncode, 0)
        self.labmode("exercise", "t2")
        r = self.ops("exercise", "start", "ex-1", "--target", "t1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("labmode.py select t1", r.stderr)
        self.assertEqual(self.markers(), [])

    def test_start_refuses_a_second_active_exercise(self):
        self.start()
        r = self.ops("exercise", "start", "ex-002", "--target", "t1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ex-001", r.stderr)
        self.assertEqual(len(self.markers()), 1)

    def test_start_refuses_at_the_high_watermark(self):
        self.es.disk_percent = 90
        r = self.ops("exercise", "start", "ex-001", "--target", "t1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("watermark", r.stderr)
        self.assertEqual(self.markers(), [])

    def test_start_refuses_when_elastic_is_down(self):
        self.es.down = True
        self.assertNotEqual(self.ops("exercise", "start", "ex-001", "--target", "t1").returncode, 0)

    def test_end_writes_the_end_marker_and_frees_the_slot(self):
        self.start()
        self.assertEqual(self.ops("exercise", "end").returncode, 0)
        self.assertEqual([m["event"]["action"] for m in self.markers()], ["exercise-start", "exercise-end"])
        self.start("ex-002")

    def test_end_without_an_active_exercise_is_refused(self):
        self.assertNotEqual(self.ops("exercise", "end").returncode, 0)

    def test_show_prints_the_time_window_from_the_markers(self):
        self.start()
        self.ops("exercise", "end")
        r = self.ops("exercise", "show", "ex-001")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("t1", r.stdout)
        self.assertIn("start", r.stdout)
        self.assertIn("end", r.stdout)
        self.assertNotEqual(self.ops("exercise", "show", "nope").returncode, 0)

    def test_generation_can_be_aligned_with_the_target(self):
        self.assertEqual(self.ops("generation", "t1", "4").returncode, 0)
        self.start()
        self.assertEqual(self.markers()[0]["lab"]["rebuild_generation"], 4)


class Drain(OpsCase):
    def test_drain_passes_when_the_marker_arrives_with_the_matching_generation(self):
        r = self.ops("drain", "t1")
        self.assertEqual(r.returncode, 0, r.stderr)
        (call,) = [json.loads(c) for c in self.stub_calls()]
        self.assertIn("opaleye@10.77.11.10", call)
        self.assertIn("drain.log", call[-1])
        self.assertIn("rebuild_generation=1", call[-1])

    def test_drain_fails_when_the_marker_never_arrives(self):
        r = self.ops("drain", "t1", STUB_DROP="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not drained", r.stderr)

    def test_drain_fails_on_a_generation_mismatch(self):
        self.assertEqual(self.ops("drain", "t1", STUB_GENERATION="9").returncode, 1)

    def test_drain_fails_when_the_target_cannot_be_reached(self):
        self.assertEqual(self.ops("drain", "t1", STUB_RC="255").returncode, 1)


class Reset(OpsCase):
    def test_reset_refuses_anything_but_a_target(self):
        for name in ("elastic", "firewall", "attacker", "all", "t9"):
            r = self.ops("reset", name)
            self.assertNotEqual(r.returncode, 0, name)
        self.assertEqual(self.stub_calls(), [])
        self.assertEqual(self.es.deletes(), [])

    def test_reset_refuses_during_an_active_exercise_on_that_target(self):
        self.start()
        r = self.ops("reset", "t1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exercise", r.stderr)
        self.assertEqual(self.stub_calls(), [])

    def test_reset_refuses_during_an_elastic_outage_even_with_acknowledged_loss(self):
        self.es.down = True
        r = self.ops("reset", "t1", "--acknowledge-loss", "testing")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.stub_calls(), [])

    def test_failed_drain_refuses_the_rebuild(self):
        r = self.ops("reset", "t1", STUB_DROP="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(len(self.stub_calls()), 1)  # only the drain ssh; nothing rebuilt
        self.assertNotIn("replace", self.stub_calls()[0])

    def test_acknowledged_loss_overrides_a_failed_drain_and_is_audited(self):
        r = self.ops("reset", "t1", "--acknowledge-loss", "agent wedged", STUB_DROP="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        last = self.audit()[-1]
        self.assertEqual((last["event"], last["acknowledged_loss"]), ("reset", "agent wedged"))

    def test_reset_rebuilds_only_the_target_stack_and_bumps_the_generation(self):
        r = self.ops("reset", "t1")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.stub_calls()
        replace = [c for c in calls if c.startswith("replace|")]
        self.assertEqual(replace, ['replace|targets|proxmox_virtual_environment_vm.target["t1"]|TF={"t1": 2, "t2": 1}'])
        self.assertTrue(any(c.startswith("playbooks/targets.yml|--limit|t1|") and "rebuild_generation=2" in c for c in calls))
        self.assertTrue(all("elastic" not in c.lower() for c in calls if not c.startswith("[")))
        self.assertEqual(self.es.deletes(), [])
        gen = self.ops("generation", "t1")
        self.assertEqual(gen.stdout.strip(), "2")
        self.assertEqual(self.pve.calls, [])  # no Proxmox call from the ops process

    def test_reset_retires_only_that_targets_agent(self):
        self.ops("reset", "t1")
        (body,) = [b for m, p, b in self.es.calls if p == "/api/fleet/agents/bulk_unenroll"]
        self.assertIn("opaleye-t1", body["agents"])
        self.assertNotIn("t2", body["agents"])
        self.assertTrue(body["revoke"])

    def test_a_failed_agent_retirement_warns_and_is_recorded(self):
        self.es.fail_unenroll = True
        r = self.ops("reset", "t1")
        self.assertEqual(r.returncode, 0)
        self.assertIn("WARNING", r.stderr)
        self.assertTrue(self.audit()[-1]["agent_retired"] is False)

    def test_a_failed_rebuild_keeps_the_generation(self):
        r = self.ops("reset", "t1", STUB_CMD_RC="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.ops("generation", "t1").stdout.strip(), "1")

    def test_reset_never_issues_an_elastic_delete(self):
        self.ops("reset", "t1")
        self.ops("reset", "t1", "--acknowledge-loss", "x", STUB_DROP="1")
        self.assertEqual(self.es.deletes(), [])


class Shutdown(OpsCase):
    def vm_ops(self, action):
        return [int(p.split("/")[6]) for m, p in self.pve.paths() if p.endswith("/status/" + action)]

    def test_shutdown_powers_off_the_guests_but_not_elastic_by_default(self):
        r = self.ops("shutdown")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.vm_ops("shutdown"), [AT, T1, T2, FW])
        self.assertEqual(self.pve.vms[EL], "running")
        self.assertIn("Elastic left running", r.stdout)
        self.assertEqual(self.es.calls, [])
        self.assertTrue(all(t != "el!t=2" for _, _, t in self.pve.calls))

    def test_include_elastic_is_a_graceful_shutdown_only_and_never_a_delete(self):
        r = self.ops("shutdown", "--include-elastic")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.vm_ops("shutdown"), [AT, T1, T2, EL, FW])
        self.assertTrue(all(m in ("GET", "POST") for m, _ in self.pve.paths()))
        self.assertTrue(all(p.endswith(("/status/current", "/status/shutdown")) for _, p in self.pve.paths()))
        self.assertEqual(self.es.calls, [])

    def test_shutdown_is_refused_during_an_active_exercise(self):
        self.start()
        self.assertNotEqual(self.ops("shutdown").returncode, 0)
        self.assertEqual(self.pve.calls, [])

    def test_stopped_guests_are_skipped(self):
        self.pve.vms[T2] = "stopped"
        self.ops("shutdown")
        self.assertNotIn(T2, self.vm_ops("shutdown"))

    def test_a_guest_that_will_not_stop_fails_the_run_and_is_never_forced(self):
        self.pve.stuck.add(T1)
        r = self.ops("shutdown", LABOPS_SHUTDOWN_WAIT="0.3")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(str(T1), r.stderr)
        self.assertTrue(all("/status/stop" not in p for _, p in self.pve.paths()))

    def test_startup_starts_firewall_first(self):
        for v in self.pve.vms:
            self.pve.vms[v] = "stopped"
        r = self.ops("startup", "--include-elastic")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.vm_ops("start"), [FW, EL, T2, T1, AT])


class AttackerClean(OpsCase):
    def test_attacker_clean_runs_on_the_attacker_only(self):
        r = self.ops("attacker-clean")
        self.assertEqual(r.returncode, 0, r.stderr)
        (call,) = [json.loads(c) for c in self.stub_calls()]
        self.assertIn("opaleye@10.77.1.10", call)
        self.assertIn("/srv/exercise", call[-1])


if __name__ == "__main__":
    unittest.main()
