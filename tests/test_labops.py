"""Operator commands (issue #24): exercise markers, drain check, target reset, lab shutdown/startup.

Run as the operator runs them (CLI), against fake Elasticsearch/Proxmox and stub ssh/lab.sh/ansible.
"""
import datetime
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
from fake_es_ops import FakeEs  # noqa: E402
from fake_pve import FakePve  # noqa: E402

PLAN = json.load(open(os.path.join(ROOT, "network/plan.json")))
FW, EL, AT = PLAN["firewall"]["vm_id"], PLAN["elastic"]["vm_id"], PLAN["attacker"]["vm_id"]
GW = PLAN["gateway"]["vm_id"]
T1 = PLAN["targets"]["t1"]["vm_id"]


class OpsCase(unittest.TestCase):
    def setUp(self):
        self.es = FakeEs()
        self.pve = FakePve({FW: "running", EL: "running", AT: "running", GW: "running", T1: "running"})
        self.dir = tempfile.mkdtemp()
        self.state = os.path.join(self.dir, "state")
        os.makedirs(self.state)
        self.log = os.path.join(self.dir, "stub.log")
        self.gen = os.path.join(self.dir, "gen")
        os.makedirs(self.gen)
        open(self.log, "w").close()
        pw = os.path.join(self.dir, "pw")
        with open(pw, "w") as f:
            f.write("pw\n")
        self.env = dict(
            os.environ, LABMODE_STATE_DIR=self.state, LABOPS_SSH=os.path.join(HERE, "stub_ssh.py"),
            LABOPS_TARGET_SH=os.path.join(HERE, "stub_target.sh"), STUB_GEN_DIR=self.gen,
            LABOPS_POLL="0.05", LABOPS_DRAIN_TIMEOUT="1", STUB_LOG=self.log, FAKE_ES_URL=self.es.url,
            ELASTIC_ES_URL=self.es.url, ELASTIC_KB_URL=self.es.url, ELASTIC_PASSWORD_FILE=pw,
            PROXMOX_VE_ENDPOINT=self.pve.url, PVE_NODE="n1",
            PROXMOX_VE_API_TOKEN_FIREWALL="fw!t=1", PROXMOX_VE_API_TOKEN_ELASTIC="el!t=2",
            PROXMOX_VE_API_TOKEN_TARGETS="tg!t=3", PROXMOX_VE_API_TOKEN_ATTACKER="at!t=4",
            PROXMOX_VE_API_TOKEN_GATEWAY="gw!t=5")
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


class Watermark(OpsCase):
    """`labops.py watermark`: the scheduled-check fallback for the high-watermark alert (Basic license, #9)."""

    def test_ok_below_the_limit(self):
        self.es.disk_percent = 42
        r = self.ops("watermark")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok", r.stdout)
        self.assertIn("42", r.stdout)

    def test_alert_at_the_limit_exits_non_zero(self):
        self.es.disk_percent = 90
        r = self.ops("watermark")
        self.assertEqual(r.returncode, 1)
        self.assertIn("ALERT", r.stderr)
        self.assertIn("90", r.stderr)

    def test_alert_is_recorded_in_the_audit_log(self):
        self.es.disk_percent = 95
        self.ops("watermark")
        self.assertEqual(self.audit()[-1]["event"], "watermark-alert")

    def test_an_unassigned_shard_row_does_not_break_the_check(self):
        self.es.unassigned_row = True
        self.es.disk_percent = 42
        r = self.ops("watermark")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("42", r.stdout)
        self.es.disk_percent = 95
        r = self.ops("watermark")
        self.assertEqual(r.returncode, 1)
        self.assertIn("ALERT", r.stderr)

    def test_exercise_start_survives_an_unassigned_shard_row(self):
        self.es.unassigned_row = True
        self.start()

    def test_the_check_never_rewrites_the_state_file(self):
        # Cron runs this beside the other commands: a stale rewrite of labops.json would drop an active exercise.
        self.start()
        path = os.path.join(self.state, "labops.json")
        before = open(path).read()
        self.es.disk_percent = 95
        self.ops("watermark")
        self.assertEqual(open(path).read(), before)
        self.assertEqual(json.loads(before)["active"]["id"], "ex-001")

    def test_an_outage_is_an_error_not_an_ok(self):
        self.es.down = True
        r = self.ops("watermark")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("ok", r.stdout)


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

    def target_event(self, ts, target="t1", generation=1):
        doc = {"@timestamp": ts, "lab": {"target_id": target, "rebuild_generation": generation}}
        self.es.add("logs-apache.access-default", doc)
        return doc

    def test_end_stamps_the_exercise_id_on_that_targets_events_inside_the_window_only(self):
        before = self.target_event("2000-01-01T00:00:00.000Z")
        self.start()
        started = self.markers()[0]["@timestamp"]
        inside = self.target_event(started)
        other_target = self.target_event(started, target="t2")
        old_generation = self.target_event(started, generation=0)
        r = self.ops("exercise", "end")
        self.assertEqual(r.returncode, 0, r.stderr)
        after = self.target_event("2999-01-01T00:00:00.000Z")
        self.assertEqual(inside["lab"]["exercise_id"], "ex-001")
        for untouched in (before, other_target, old_generation, after):
            self.assertNotIn("exercise_id", untouched["lab"])
        self.assertIn("tagged 1 events", r.stdout)

    def test_tagging_allows_for_clock_skew_just_outside_the_markers(self):
        self.start()
        started = datetime.datetime.fromisoformat(self.markers()[0]["@timestamp"].replace("Z", "+00:00"))

        def at(seconds):
            return (started + datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        just_before, far_before = self.target_event(at(-2)), self.target_event(at(-60))
        self.ops("exercise", "end")
        self.assertEqual(just_before["lab"].get("exercise_id"), "ex-001")
        self.assertNotIn("exercise_id", far_before["lab"])

    def test_tag_picks_up_events_that_arrived_after_the_end(self):
        self.start()
        self.ops("exercise", "end")
        late = self.target_event(self.markers()[0]["@timestamp"])
        r = self.ops("exercise", "tag", "ex-001")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(late["lab"]["exercise_id"], "ex-001")

    def test_tag_refuses_an_exercise_without_both_markers(self):
        self.start()
        self.assertNotEqual(self.ops("exercise", "tag", "ex-001").returncode, 0)
        self.assertNotEqual(self.ops("exercise", "tag", "nope").returncode, 0)

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

    def test_the_marker_carries_the_generation_target_sh_reports(self):
        with open(os.path.join(self.gen, "t1"), "w") as f:
            f.write("4\n")
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
    def setUp(self):
        super().setUp()
        self.labmode("maintenance", None)  # provisioning needs maintenance mode

    def target_calls(self):
        return [c for c in self.stub_calls() if not c.startswith("[")]

    def test_reset_refuses_anything_but_a_target_with_a_vm(self):
        for name in ("elastic", "firewall", "attacker", "all", "t9", "t2"):
            r = self.ops("reset", name)
            self.assertNotEqual(r.returncode, 0, name)
        self.assertEqual(self.stub_calls(), [])
        self.assertEqual(self.es.deletes(), [])

    def test_reset_refuses_outside_maintenance_mode_before_changing_anything(self):
        self.labmode("exercise", "t1")
        r = self.ops("reset", "t1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("maintenance", r.stderr)
        self.assertEqual(self.stub_calls(), [])

    def test_reset_refuses_during_an_active_exercise_on_that_target(self):
        self.labmode("exercise", "t1")
        self.start()
        self.labmode("maintenance", None)
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
        self.assertEqual(self.target_calls(), [])
        self.assertEqual(len(self.stub_calls()), 1)  # only the drain ssh

    def test_acknowledged_loss_overrides_a_failed_drain_and_is_audited(self):
        r = self.ops("reset", "t1", "--acknowledge-loss", "agent wedged", STUB_DROP="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        last = self.audit()[-1]
        self.assertEqual((last["event"], last["acknowledged_loss"]), ("reset", "agent wedged"))

    def test_an_acknowledged_loss_needs_a_real_reason(self):
        for reason in ("", "  ", "ok"):
            self.assertNotEqual(self.ops("reset", "t1", "--acknowledge-loss", reason, STUB_DROP="1").returncode, 0)
        self.assertEqual(self.stub_calls(), [])

    def test_reset_bumps_then_provisions_only_that_target_through_target_sh(self):
        r = self.ops("reset", "t1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.target_calls(), ["bump|bump t1 --acknowledge-no-drain-check", "provision|provision t1"])
        self.assertEqual(self.ops("generation", "t1").stdout.strip(), "2")
        self.assertEqual(self.es.deletes(), [])
        self.assertEqual(self.pve.calls, [])

    def test_a_failed_bump_provisions_nothing(self):
        r = self.ops("reset", "t1", STUB_FAIL="bump")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.target_calls(), ["bump|bump t1 --acknowledge-no-drain-check"])
        self.assertEqual(self.ops("generation", "t1").stdout.strip(), "1")

    def test_a_failed_provision_says_to_rerun_provision_not_to_repair(self):
        r = self.ops("reset", "t1", STUB_FAIL="provision")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("target.sh provision t1", r.stderr)
        self.assertEqual(self.ops("generation", "t1").stdout.strip(), "2")  # already bumped: provision converges to it

    def test_reset_never_issues_an_elastic_delete(self):
        self.ops("reset", "t1")
        self.ops("reset", "t1", "--acknowledge-loss", "reason given", STUB_DROP="1")
        self.assertEqual(self.es.deletes(), [])


class Shutdown(OpsCase):
    def vm_ops(self, action):
        return [int(p.split("/")[6]) for m, p in self.pve.paths() if p.endswith("/status/" + action)]

    def test_shutdown_powers_off_the_guests_but_not_elastic_by_default(self):
        r = self.ops("shutdown")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.vm_ops("shutdown"), [GW, AT, T1, FW])
        self.assertEqual(self.pve.vms[EL], "running")
        self.assertIn("Elastic left running", r.stdout)
        self.assertEqual(self.es.deletes(), [])
        self.assertEqual([p for _, p, _ in self.es.calls if "unenroll" in p], [])
        self.assertTrue(all(t != "el!t=2" for _, _, t in self.pve.calls))

    def test_include_elastic_is_a_graceful_shutdown_only_and_never_a_delete(self):
        r = self.ops("shutdown", "--include-elastic")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.vm_ops("shutdown"), [GW, AT, T1, EL, FW])
        self.assertTrue(all(m in ("GET", "POST") for m, _ in self.pve.paths()))
        self.assertTrue(all(p.endswith(("/status/current", "/status/shutdown")) for _, p in self.pve.paths()))
        self.assertEqual(self.es.deletes(), [])

    def test_shutdown_drains_running_targets_first(self):
        self.ops("shutdown")
        drained = [json.loads(c)[-2] for c in self.stub_calls()]
        self.assertEqual(drained, ["opaleye@10.77.11.10"])

    def test_a_failed_drain_stops_the_shutdown_before_anything_is_powered_off(self):
        r = self.ops("shutdown", STUB_DROP="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.vm_ops("shutdown"), [])

    def test_shutdown_during_an_elastic_outage_needs_acknowledged_loss(self):
        self.es.down = True
        self.assertNotEqual(self.ops("shutdown").returncode, 0)
        self.assertEqual(self.vm_ops("shutdown"), [])
        r = self.ops("shutdown", "--acknowledge-loss", "elastic is down", STUB_DROP="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.vm_ops("shutdown"), [GW, AT, T1, FW])

    def test_shutdown_is_refused_during_an_active_exercise(self):
        self.start()
        self.assertNotEqual(self.ops("shutdown").returncode, 0)
        self.assertEqual(self.pve.calls, [])

    def test_a_stopped_target_is_skipped_and_not_drained(self):
        self.pve.vms[T1] = "stopped"
        self.ops("shutdown")
        self.assertNotIn(T1, self.vm_ops("shutdown"))
        self.assertEqual(self.stub_calls(), [])

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
        self.assertEqual(self.vm_ops("start"), [FW, EL, T1, AT, GW])


class AttackerClean(OpsCase):
    def test_attacker_clean_runs_on_the_attacker_only(self):
        r = self.ops("attacker-clean")
        self.assertEqual(r.returncode, 0, r.stderr)
        (call,) = [json.loads(c) for c in self.stub_calls()]
        self.assertIn("opaleye@10.77.1.10", call)
        self.assertIn("/srv/exercise", call[-1])


class Analysis(OpsCase):
    """#52: analysis zone commands. labmode.py / fleetctl.py are stubbed; ssh, Proxmox and Elasticsearch are fakes."""

    def setUp(self):
        super().setUp()
        self.vm = {h: v["vm_id"] for h, v in PLAN["analysis"]["hosts"].items()}
        for vmid in self.vm.values():
            self.pve.vms[vmid] = "running"
        self.env.update(
            LABOPS_LABMODE="%s %s" % (pathlib.Path(sys.executable).as_posix(), pathlib.Path(HERE, "stub_labmode.py").as_posix()),
            LABOPS_FLEETCTL="%s %s" % (pathlib.Path(sys.executable).as_posix(), pathlib.Path(HERE, "stub_fleetctl.py").as_posix()),
            LABOPS_SSH="%s %s" % (pathlib.Path(sys.executable).as_posix(), pathlib.Path(HERE, "stub_ssh.py").as_posix()),
            PROXMOX_VE_API_TOKEN_ANALYSIS="an!t=6", LABOPS_SHUTDOWN_WAIT="2")

    def lines(self, prefix):
        return [c for c in self.stub_calls() if c.startswith(prefix)]

    def test_online_delegates_to_labmode_and_is_audited(self):
        r = self.ops("analysis-online", "on", "--minutes", "10")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.lines("labmode|"), ["labmode|analysis on --minutes 10"])
        self.assertIn("BEFORE detonating", r.stdout)
        self.assertEqual(self.audit()[-1]["event"], "analysis-online-on")

    def test_online_failure_is_passed_on(self):
        self.assertNotEqual(self.ops("analysis-online", "off", STUB_FAIL="labmode").returncode, 0)

    def test_reset_forces_internet_off_first_then_drains_reverts_and_re_enrols_each_host(self):
        r = self.ops("analysis-reset")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.stub_calls()
        self.assertEqual(calls[0], "labmode|analysis off")
        self.assertEqual(sorted(self.pve.rollbacks), sorted((vmid, "clean") for vmid in self.vm.values()))
        self.assertEqual(sorted(self.lines("fleetctl|issue-token")), ["fleetctl|issue-token flare 2", "fleetctl|issue-token remnux 2"])
        self.assertEqual(sorted(self.lines("fleetctl|register-agent")), ["fleetctl|register-agent flare 2", "fleetctl|register-agent remnux 2"])
        self.assertEqual([e["generation"] for e in self.audit() if e["event"] == "analysis-reverted"], [2, 2])
        self.assertTrue(all(status == "running" for status in (self.pve.vms[v] for v in self.vm.values())))

    def test_generation_increments_on_each_reset(self):
        self.ops("analysis-reset", "remnux")
        self.ops("analysis-reset", "remnux")
        self.assertEqual(self.lines("fleetctl|issue-token"), ["fleetctl|issue-token remnux 2", "fleetctl|issue-token remnux 3"])

    def test_hosts_are_reached_through_the_gateway_only(self):
        self.ops("analysis-reset", "flare")
        ssh = [json.loads(c) for c in self.stub_calls() if c.startswith("[")]
        self.assertTrue(ssh)
        for argv in ssh:
            self.assertIn("-J", argv)
            self.assertEqual(argv[argv.index("-J") + 1], "opaleye@" + PLAN["hosts"]["gateway"]["ip"])
            self.assertTrue(argv[-2].endswith("@" + PLAN["hosts"]["flare"]["ip"]))

    def test_the_enrolment_token_travels_on_stdin_never_in_an_argument(self):
        self.ops("analysis-reset", "remnux")
        self.assertEqual(self.lines("stdin|"), ["stdin|TOKEN-remnux-2"])
        self.assertNotIn("TOKEN-remnux-2", "\n".join(c for c in self.stub_calls() if c.startswith("[")))

    def test_a_failed_drain_blocks_the_revert_unless_the_loss_is_acknowledged(self):
        r = self.ops("analysis-reset", STUB_DROP="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("drain check failed", r.stderr)
        self.assertEqual(self.pve.rollbacks, [])
        r = self.ops("analysis-reset", "remnux", "--acknowledge-loss", "forwarding broken", STUB_DROP="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.pve.rollbacks, [(self.vm["remnux"], "clean")])

    def test_if_internet_cannot_be_switched_off_nothing_is_reverted(self):
        r = self.ops("analysis-reset", STUB_FAIL="labmode")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.pve.rollbacks, [])

    def test_a_stopped_vm_is_not_drained_and_stays_off_after_the_revert(self):
        self.pve.vms[self.vm["flare"]] = "stopped"
        r = self.ops("analysis-reset", "flare", STUB_DROP="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.pve.vms[self.vm["flare"]], "stopped")
        self.assertEqual(self.pve.rollbacks, [(self.vm["flare"], "clean")])

    def test_only_the_analysis_token_is_used_for_the_revert(self):
        self.ops("analysis-reset", "remnux")
        snap = [t for m, p, t in self.pve.calls if "/snapshot/" in p]
        self.assertEqual(snap, ["PVEAPIToken=an!t=6"])

    def test_unknown_host_is_refused(self):
        r = self.ops("analysis-reset", "t1")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.pve.rollbacks, [])

    def test_a_token_failure_is_reported_after_the_revert(self):
        r = self.ops("analysis-reset", "remnux", STUB_FAIL="token")
        self.assertEqual(r.returncode, 1)
        self.assertIn("enrolment failed", r.stderr)

    def test_sample_markers_and_stamping(self):
        self.assertEqual(self.ops("analysis-sample", "start", "emotet-001").returncode, 0)
        self.es.add("logs-system.syslog-analysis", {"@timestamp": "2099-01-01T00:00:00.000Z", "lab": {"zone": "analysis"}})
        self.es.add("logs-apache.access-default", {"@timestamp": "2099-01-01T00:00:00.000Z", "lab": {"zone": "other"}})
        # widen the window past the fake events: end writes its marker "now", so back-date the start
        path = os.path.join(self.state, "labops.json")
        st = json.load(open(path))
        st["sample"]["started"] = "2000-01-01T00:00:00.000Z"
        json.dump(st, open(path, "w"))
        self.es.docs["logs-system.syslog-analysis"][0]["@timestamp"] = "2020-01-01T00:00:00.000Z"
        self.es.docs["logs-apache.access-default"][0]["@timestamp"] = "2020-01-01T00:00:00.000Z"
        r = self.ops("analysis-sample", "end")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.es.docs["logs-system.syslog-analysis"][0]["lab"]["sample_id"], "emotet-001")
        self.assertNotIn("sample_id", self.es.docs["logs-apache.access-default"][0]["lab"])
        actions = [m["event"]["action"] for m in self.markers()]
        self.assertEqual(actions, ["sample-start", "sample-end"])

    def test_one_sample_at_a_time_and_reset_refuses_during_one(self):
        self.ops("analysis-sample", "start", "emotet-001")
        self.assertNotEqual(self.ops("analysis-sample", "start", "other-002").returncode, 0)
        r = self.ops("analysis-reset")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.pve.rollbacks, [])

    def test_sample_id_must_be_well_formed(self):
        self.assertNotEqual(self.ops("analysis-sample", "start", "Bad ID").returncode, 0)


if __name__ == "__main__":
    unittest.main()
