"""The job inside the Rust reusable that fails when a selected job did not end in success.

The job that calls a reusable ends in success when every job inside it is
skipped, so the reusable carries its own check, run here as written.
"""

import os
import subprocess
import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
REUSABLE = ROOT / ".github/workflows/reusable-rust-ci.yml"
NAMES = ("LINT", "TEST", "COVERAGE", "SUITE", "MSRV", "DOC", "PACKAGE", "SEMVER")


def jobs():
    return ci_yaml.load(REUSABLE)["jobs"]


def run(want, got, extra="success"):
    env = {f"WANT_{n}": want.get(n, "false") for n in NAMES}
    env.update({f"GOT_{n}": got.get(n, "skipped") for n in NAMES})
    env["GOT_EXTRA"] = extra
    done = subprocess.run(["bash", "-e", "-c", jobs()["sentinel"]["steps"][0]["run"]], capture_output=True, text=True,
                          env={**os.environ, **env}, check=False)
    return done.returncode, done.stdout + done.stderr


EVERYTHING = {"LINT": "true", "TEST": "true", "COVERAGE": "true", "MSRV": "true", "DOC": "true"}
ALL_OK = {"LINT": "success", "TEST": "success", "COVERAGE": "success", "MSRV": "success", "DOC": "success"}


class Decisions(unittest.TestCase):
    def test_everything_selected_and_green_passes(self):
        self.assertEqual(run(EVERYTHING, ALL_OK)[0], 0)

    def test_nothing_selected_and_everything_skipped_passes(self):
        self.assertEqual(run({}, {})[0], 0)

    def test_a_selected_job_that_was_skipped_fails_for_each_job(self):
        for name in ("LINT", "TEST", "COVERAGE", "MSRV", "DOC"):
            with self.subTest(name=name):
                code, out = run(EVERYTHING, {**ALL_OK, name: "skipped"})
                self.assertEqual(code, 1, out)
                self.assertIn(f"{name} was selected and ended in skipped", out)

    def test_a_selected_job_that_failed_or_was_cancelled_fails(self):
        for result in ("failure", "cancelled"):
            self.assertEqual(run(EVERYTHING, {**ALL_OK, "COVERAGE": result})[0], 1)

    def test_a_job_that_was_not_selected_but_failed_still_fails(self):
        for result in ("failure", "cancelled"):
            code, out = run({}, {"LINT": result})
            self.assertEqual(code, 1, out)

    def test_a_job_that_was_not_selected_but_ran_is_not_a_problem(self):
        self.assertEqual(run({}, {"LINT": "success"})[0], 0)

    def test_the_plain_suite_is_the_one_required_when_coverage_is_off(self):
        want = {"TEST": "true", "SUITE": "true"}
        self.assertEqual(run(want, {"TEST": "success", "SUITE": "success"})[0], 0)
        self.assertEqual(run(want, {"TEST": "success", "SUITE": "skipped"})[0], 1)

    def test_the_extra_platforms_failing_fails(self):
        self.assertEqual(run({}, {}, extra="failure")[0], 1)
        self.assertEqual(run({}, {}, extra="cancelled")[0], 1)

    def test_a_selection_that_is_not_a_boolean_fails(self):
        for value in ("", "yes", "True"):
            with self.subTest(value=value):
                code, out = run({"LINT": value}, ALL_OK)
                self.assertEqual(code, 1, out)
                self.assertIn("neither true nor false", out)


class Wiring(unittest.TestCase):
    def test_it_always_runs_and_waits_for_every_other_job(self):
        sentinel = jobs()["sentinel"]
        self.assertEqual(sentinel["if"], "always()")
        self.assertEqual(set(sentinel["needs"]), set(jobs()) - {"sentinel", "extra-platforms-gate", "msrv-gate"})

    def test_what_it_reads_is_what_the_inputs_and_the_needs_say(self):
        env = jobs()["sentinel"]["steps"][0]["env"]
        for name, job in (("LINT", "lint"), ("TEST", "test"), ("COVERAGE", "coverage"), ("SUITE", "test-suite"),
                          ("MSRV", "msrv"), ("DOC", "doc"), ("PACKAGE", "package"), ("SEMVER", "semver"),
                          ("EXTRA", "test-extra")):
            self.assertEqual(env[f"GOT_{name}"], "${{ needs." + job + ".result }}")
        self.assertEqual(env["WANT_LINT"], "${{ inputs.run-lint }}")
        self.assertEqual(env["WANT_TEST"], "${{ inputs.run-tests }}")
        self.assertEqual(env["WANT_COVERAGE"], "${{ inputs.run-tests && inputs.coverage-threshold > 0 }}")
        self.assertEqual(env["WANT_SUITE"], "${{ inputs.run-tests && inputs.coverage-threshold == 0 }}")
        self.assertEqual(env["WANT_MSRV"], "${{ inputs.run-msrv && inputs.msrv != '' }}")
        self.assertEqual(env["WANT_DOC"], "${{ inputs.doc-warnings }}")

    def test_it_is_a_single_step_with_no_continue_on_error(self):
        sentinel = jobs()["sentinel"]
        self.assertEqual(len(sentinel["steps"]), 1)
        self.assertNotIn("continue-on-error", sentinel)
        self.assertNotIn("continue-on-error", sentinel["steps"][0])
        self.assertNotIn("shell", sentinel["steps"][0])
        self.assertNotIn("${{", sentinel["steps"][0]["run"])


if __name__ == "__main__":
    unittest.main()
