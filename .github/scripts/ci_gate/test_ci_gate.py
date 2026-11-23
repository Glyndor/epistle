"""The `CI gate` job of ci.yml: what it accepts, what it refuses, and how it is wired.

The cases run the step of the workflow as written, so the test and the
workflow cannot drift apart.
"""

import json
import os
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
CI = ROOT / ".github/workflows/ci.yml"
SUITES = {
    "rust": ("lint", "tests", "doc", "msrv"),
    "debian": ("debian",),
    "line-limit": ("lines",),
    "sbom-and-licenses": ("supply",),
    "wiring": ("wiring",),
}
# Jobs of ci.yml the gate does not wait for, each with the reason.
OUTSIDE = {
    "dependabot-freshness": "reads the age of the newest Dependabot pull request, not the commit",
}


def workflow():
    return yaml.safe_load(CI.read_text())


def gate_step():
    return workflow()["jobs"]["gate"]["steps"][0]["run"]


def plan(**overrides):
    """A successful plan that selects every job, with some outputs changed."""
    outputs = {dim: "true" for dims in SUITES.values() for dim in dims}
    outputs.update(freshness="true", folder="true")
    outputs.update(overrides)
    return {"result": "success", "outputs": outputs}


def needs(plan_=None, **results):
    """The `needs` context: a plan and one result per suite (success by default)."""
    context = {"plan": plan_ or plan()}
    for suite in SUITES:
        context[suite] = {"result": results.pop(suite, "success"), "outputs": {}}
    assert not results, results
    return context


def run_gate(context):
    done = subprocess.run(
        ["bash", "-e", "-c", gate_step()],
        env={**os.environ, "NEEDS": json.dumps(context)},
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode, done.stdout + done.stderr


class GateDecisions(unittest.TestCase):
    def passes(self, context):
        code, out = run_gate(context)
        self.assertEqual(code, 0, out)

    def fails(self, context, fragment):
        code, out = run_gate(context)
        self.assertEqual(code, 1, out)
        self.assertIn(fragment, out)

    def test_every_suite_green_passes(self):
        self.passes(needs())

    def test_a_failed_plan_fails_even_if_every_suite_ran(self):
        failed = needs(plan_={"result": "failure", "outputs": {}})
        self.fails(failed, "the plan job did not succeed (result: failure)")

    def test_a_failed_plan_fails_when_the_suites_were_skipped_behind_it(self):
        behind = needs(plan_={"result": "failure", "outputs": {}}, **dict.fromkeys(SUITES, "skipped"))
        self.fails(behind, "the plan job did not succeed")

    def test_a_cancelled_plan_fails(self):
        self.fails(needs(plan_={"result": "cancelled", "outputs": {}}), "result: cancelled")

    def test_a_suite_skipped_although_the_plan_selected_it_fails(self):
        for suite, dims in SUITES.items():
            with self.subTest(suite=suite):
                self.fails(needs(**{suite: "skipped"}), f"{suite} was skipped and the plan did not say it could be")

    def test_a_suite_skipped_because_the_plan_said_so_passes(self):
        for suite, dims in SUITES.items():
            with self.subTest(suite=suite):
                self.passes(needs(plan_=plan(**dict.fromkeys(dims, "false")), **{suite: "skipped"}))

    def test_a_plan_that_skips_everything_passes_only_with_every_suite_skipped(self):
        everything = plan(**{dim: "false" for dims in SUITES.values() for dim in dims})
        self.passes(needs(plan_=everything, **dict.fromkeys(SUITES, "skipped")))
        self.fails(needs(plan_=everything, rust="failure", **{s: "skipped" for s in SUITES if s != "rust"}), "rust did not succeed")

    def test_rust_may_be_skipped_only_when_the_plan_skips_all_four_kinds_of_work(self):
        for kept in SUITES["rust"]:
            with self.subTest(kept=kept):
                partial = plan(**{dim: "false" for dim in SUITES["rust"] if dim != kept})
                self.fails(needs(plan_=partial, rust="skipped"), "rust was skipped and the plan did not say it could be")

    def test_a_failed_or_cancelled_suite_fails_whatever_the_plan_said(self):
        for result in ("failure", "cancelled"):
            for suite, dims in SUITES.items():
                with self.subTest(result=result, suite=suite):
                    self.fails(needs(plan_=plan(**dict.fromkeys(dims, "false")), **{suite: result}), f"{suite} did not succeed (result: {result})")

    def test_a_suite_that_ran_although_the_plan_skipped_it_still_passes(self):
        self.passes(needs(plan_=plan(debian="false")))

    def test_an_output_that_is_missing_or_not_a_boolean_fails(self):
        for value in ("", "maybe", None):
            with self.subTest(value=value):
                broken = plan()
                if value is None:
                    del broken["outputs"]["tests"]
                else:
                    broken["outputs"]["tests"] = value
                self.fails(needs(plan_=broken), "plan output 'tests' is neither true nor false")

    def test_an_output_that_is_not_a_boolean_never_licenses_a_skip(self):
        self.fails(needs(plan_=plan(debian=""), debian="skipped"), "debian was skipped and the plan did not say it could be")

    def test_a_suite_the_gate_does_not_wait_for_fails(self):
        context = needs()
        del context["debian"]
        self.fails(context, "debian is not among the jobs the gate waits for")

    def test_a_job_the_gate_does_not_know_fails(self):
        context = needs()
        context["new-suite"] = {"result": "success", "outputs": {}}
        self.fails(context, "new-suite is not in the gate table")

    def test_a_missing_plan_fails(self):
        context = needs()
        del context["plan"]
        self.fails(context, "the plan job did not succeed")


class GateWiring(unittest.TestCase):
    def test_it_runs_always_and_waits_for_the_plan_and_every_suite(self):
        jobs = workflow()["jobs"]
        gate = jobs["gate"]
        self.assertEqual(gate["if"], "always()")
        self.assertEqual(gate["name"], "CI gate")
        self.assertEqual(set(gate["needs"]), {"plan", *SUITES})
        self.assertEqual(set(jobs) - {"gate", "plan"} - set(OUTSIDE), set(SUITES))

    def test_the_table_of_the_step_is_the_table_of_this_test(self):
        text = gate_step()
        for suite, dims in SUITES.items():
            expected = ", ".join(f'"{dim}"' for dim in dims) + ("," if len(dims) == 1 else "")
            self.assertIn(f'"{suite}": ({expected}),', text)

    def test_it_holds_no_permission_and_checks_nothing_out(self):
        gate = workflow()["jobs"]["gate"]
        self.assertEqual(gate["permissions"], {})
        self.assertEqual(len(gate["steps"]), 1)
        self.assertNotIn("uses", gate["steps"][0])

    def test_it_reads_the_context_from_the_environment_only(self):
        step = workflow()["jobs"]["gate"]["steps"][0]
        self.assertEqual(step["env"], {"NEEDS": "${{ toJSON(needs) }}"})
        self.assertNotIn("${{", step["run"])

    def test_it_uses_the_runner_variable_like_every_other_job(self):
        self.assertEqual(workflow()["jobs"]["gate"]["runs-on"], "${{ fromJSON(vars.CI_RUNNER || '\"ubuntu-latest\"') }}")

    def test_every_suite_starts_even_when_the_plan_failed(self):
        for name, job in workflow()["jobs"].items():
            if name in SUITES:
                self.assertEqual(job["needs"], "plan", name)
                self.assertEqual(job["if"], "${{ !cancelled() }}", name)
                for step in job.get("steps", []):
                    self.assertNotIn("== 'true'", str(step.get("if", "")), name)
                    if "needs.plan.outputs" in str(step.get("if", "")):
                        self.assertIn("needs.plan.outputs.wiring != 'false'", step["if"], name)

    def test_a_suite_is_skipped_only_by_an_explicit_false(self):
        for name, job in workflow()["jobs"].items():
            for text in (str(job.get("if", "")), str(job.get("with", ""))):
                self.assertNotIn("== 'true'", text, name)
                self.assertNotIn("contains(needs", text, name)
        for name in SUITES:
            for key, value in (workflow()["jobs"][name].get("with") or {}).items():
                if "needs.plan.outputs" in str(value):
                    self.assertTrue(str(value).endswith(" != 'false' }}"), f"{name}: {key}")


if __name__ == "__main__":
    unittest.main()
