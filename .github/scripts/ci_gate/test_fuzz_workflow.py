"""The fuzz workflow runs its targets in a few jobs that each build once."""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]


def fuzz():
    return ci_yaml.load(ROOT / ".github/workflows/fuzz.yml")


class Groups(unittest.TestCase):
    def test_the_matrix_is_the_groups_the_plan_makes_and_not_the_targets(self):
        job = fuzz()["jobs"]["fuzz"]
        self.assertEqual(job["strategy"]["matrix"], {"group": "${{ fromJSON(needs.plan.outputs.groups) }}"})
        self.assertEqual(fuzz()["jobs"]["plan"]["outputs"]["groups"], "${{ steps.pick.outputs.groups }}")
        self.assertEqual(job["if"], "needs.plan.outputs.targets != '[]'")

    def test_a_pull_request_stops_at_the_first_failing_group_and_a_push_reports_all(self):
        self.assertEqual(fuzz()["jobs"]["fuzz"]["strategy"]["fail-fast"], "${{ github.event_name == 'pull_request' }}")

    def test_the_job_names_the_group_and_runs_every_target_of_it_through_the_environment(self):
        job = fuzz()["jobs"]["fuzz"]
        self.assertEqual(job["name"], "cargo fuzz (group ${{ matrix.group.id }})")
        step = next(s for s in job["steps"] if s.get("name") == "Fuzz the targets of the group")
        self.assertEqual(step["env"]["TARGETS"], "${{ matrix.group.targets }}")
        self.assertNotIn("${{", step["run"])
        self.assertIn('cargo fuzz run "$target" -- -max_total_time=60 -timeout=10', step["run"])
        self.assertIn("exit \"$status\"", step["run"])

    def run_group(self, event, failing):
        step = next(s for s in fuzz()["jobs"]["fuzz"]["steps"] if s.get("name") == "Fuzz the targets of the group")["run"]
        with tempfile.TemporaryDirectory() as tmp:
            cargo = Path(tmp) / "cargo"
            log = Path(tmp) / "log"
            cargo.write_text(f'#!/bin/sh\necho "$3" >> "{log}"\n[ "$3" = "{failing}" ] && exit 1\nexit 0\n')
            cargo.chmod(cargo.stat().st_mode | stat.S_IEXEC)
            done = subprocess.run(["bash", "-c", step], capture_output=True, text=True, check=False,
                                  env={**os.environ, "PATH": f"{tmp}:{os.environ['PATH']}", "TARGETS": "a b c d",
                                       "EVENT_NAME": event})
            return done.returncode, (log.read_text().split() if log.exists() else [])

    def test_a_pull_request_stops_a_group_at_the_first_failing_target(self):
        self.assertEqual(self.run_group("pull_request", "b"), (1, ["a", "b"]))

    def test_a_push_and_the_nightly_run_run_every_target_and_still_fail(self):
        for event in ("push", "schedule", "workflow_dispatch"):
            self.assertEqual(self.run_group(event, "b"), (1, ["a", "b", "c", "d"]), event)

    def test_a_group_with_no_failure_passes(self):
        self.assertEqual(self.run_group("pull_request", "none"), (0, ["a", "b", "c", "d"]))

    def test_no_step_runs_one_job_per_target_any_more(self):
        self.assertNotIn("matrix.target", (ROOT / ".github/workflows/fuzz.yml").read_text())


if __name__ == "__main__":
    unittest.main()
