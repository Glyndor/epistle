"""The job that cancels the other runs of a failed commit: what it may cancel, and who may hold the token that can.

`actions: write` is the token that ends runs of any workflow, so every case is a way the job could cancel too much,
fail, or run code the pull request wrote. The script runs against a fake `gh`.
"""

import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / ".github/scripts/ci/cancel-others.sh"
REUSABLE = "reusable-cancel-others.yml"
CALLERS = {"ci.yml", "dco.yml", "db.yml", "e2e.yml", "upgrade.yml", "container.yml", "interop.yml", "imaptest.yml", "ldap.yml"}
SHA, OTHER_SHA = "a" * 40, "b" * 40
REPO = "o/r"
FAKE_GH = """#!/usr/bin/env bash
# A stand-in for gh: it lists the runs from $RUNS_JSON and records what is cancelled.
if [ "$1" = api ] && [ "$2" = -X ] && [ "$3" = POST ]; then
  [ "${CANCEL_FAIL:-0}" = 0 ] || exit 1
  echo "$4" >> "$CANCELLED"
  exit 0
fi
if [ "$1" = api ]; then
  [ "${LIST_FAIL:-0}" = 0 ] || exit 1
  echo "$2" > "$LISTED"
  cat "$RUNS_JSON"
  exit 0
fi
exit 2
"""


def run(number, path, event="pull_request", sha=SHA, branch="feature", repo=REPO, status="in_progress", pr=9):
    return {"id": number, "pull_requests": [{"number": pr}], "event": event, "head_sha": sha, "head_branch": branch, "status": status, "path": path,
            "head_repository": {"full_name": repo}}


class TheScript(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        gh = self.dir / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(gh.stat().st_mode | stat.S_IEXEC)

    def cancel(self, runs, own="1", env=None, **flags):
        (self.dir / "runs.json").write_text(json.dumps({"workflow_runs": runs}))
        for name in ("cancelled", "listed"):
            (self.dir / name).write_text("")
        values = {"GH_TOKEN": "t", "REPO": REPO, "RUN_ID": own, "EVENT_NAME": "pull_request", "HEAD_SHA": SHA, "HEAD_BRANCH": "feature", "PR_NUMBER": "9", **(env or {})}
        done = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, check=False, env={
            **os.environ, "PATH": f"{self.dir}:{os.environ['PATH']}", "RUNS_JSON": str(self.dir / "runs.json"),
            "CANCELLED": str(self.dir / "cancelled"), "LISTED": str(self.dir / "listed"),
            **{k: str(v) for k, v in flags.items()}, **values})
        cancelled = [line.rsplit("/", 2)[-2] for line in (self.dir / "cancelled").read_text().split()]
        return done.returncode, cancelled, done.stdout + done.stderr

    def test_it_cancels_an_unfinished_run_of_a_listed_workflow_of_the_same_commit_branch_and_repository(self):
        code, cancelled, _ = self.cancel([run(2, ".github/workflows/e2e.yml"), run(3, ".github/workflows/db.yml", status="queued")])
        self.assertEqual((code, cancelled), (0, ["2", "3"]))

    def test_it_never_cancels_what_it_must_not(self):
        runs = [
            run(2, ".github/workflows/ci.yml", event="push"),
            run(3, ".github/workflows/ci.yml", event="merge_group"),
            run(4, ".github/workflows/fuzz.yml", event="schedule"),
            run(5, ".github/workflows/ci.yml", event="workflow_dispatch"),
            run(6, ".github/workflows/e2e.yml", sha=OTHER_SHA),
            run(7, ".github/workflows/e2e.yml", branch="other"),
            run(8, ".github/workflows/e2e.yml", repo="fork/r"),
            run(9, ".github/workflows/e2e.yml", status="completed"),
            run(1, ".github/workflows/ci.yml"),  # its own run
            run(10, ".github/workflows/release.yml"),
            run(11, ".github/workflows/codeql.yml"),
            run(12, ".github/workflows/dco.yml"),
            run(13, ".github/workflows/rust-audit.yml"),
            run(14, ".github/workflows/dependabot-security-watch.yml"),
            run(15, ".github/workflows/unknown.yml"),
            run(16, ""),
        ]
        code, cancelled, out = self.cancel(runs)
        self.assertEqual((code, cancelled), (0, []), out)
        self.assertIn("kept: run 10 of .github/workflows/release.yml is not on the list", out)

    def test_a_workflow_whose_path_has_a_ref_suffix_is_matched_by_its_file(self):
        self.assertEqual(self.cancel([run(2, ".github/workflows/e2e.yml@refs/pull/9/merge")])[1], ["2"])

    def test_a_listing_that_fails_a_refused_cancellation_and_a_missing_input_never_fail_the_job(self):
        code, cancelled, out = self.cancel([run(2, ".github/workflows/e2e.yml")], LIST_FAIL=1)
        self.assertEqual((code, cancelled), (0, []))
        self.assertIn("could not be read", out)
        code, cancelled, out = self.cancel([run(2, ".github/workflows/e2e.yml")], CANCEL_FAIL=1)
        self.assertEqual(code, 0)
        self.assertIn("could not be cancelled", out)
        for missing, said in (("REPO", "nothing is cancelled"), ("RUN_ID", "nothing is cancelled"), ("HEAD_SHA", "no other run is cancelled"), ("HEAD_BRANCH", "no other run is cancelled"), ("PR_NUMBER", "no other run is cancelled")):
            code, cancelled, out = self.cancel([run(2, ".github/workflows/e2e.yml")], env={missing: ""})
            self.assertEqual((code, cancelled), (0, []), missing)
            self.assertIn(said, out, missing)

    def test_inputs_that_are_not_what_they_claim_to_be_cancel_nothing(self):
        for env in ({"HEAD_SHA": "main"}, {"HEAD_SHA": f"{SHA}; true"}, {"RUN_ID": "1; echo"}):
            code, cancelled, out = self.cancel([run(2, ".github/workflows/e2e.yml")], env=env)
            self.assertEqual((code, cancelled), (0, []), env)

    def test_with_cancel_own_the_run_of_the_job_goes_last_and_only_when_it_says_true(self):
        runs = [run(2, ".github/workflows/e2e.yml")]
        code, cancelled, out = self.cancel(runs, env={"CANCEL_OWN": "true"})
        self.assertEqual((code, cancelled), (0, ["2", "1"]), out)
        self.assertIn("cancelled: this run (1)", out)
        for value in ("", "false", "yes", "TRUE", "1"):
            self.assertEqual(self.cancel(runs, env={"CANCEL_OWN": value})[1], ["2"], value)

    def test_in_the_merge_queue_it_cancels_its_own_run_and_never_another_one(self):
        runs = [run(2, ".github/workflows/ci.yml", event="merge_group"), run(3, ".github/workflows/e2e.yml"), run(4, ".github/workflows/db.yml", event="push")]
        code, cancelled, out = self.cancel(runs, env={"EVENT_NAME": "merge_group", "CANCEL_OWN": "true", "HEAD_SHA": "", "HEAD_BRANCH": ""})
        self.assertEqual((code, cancelled), (0, ["1"]), out)
        self.assertEqual((self.dir / "listed").read_text(), "", "the runs of a queue entry are not even listed")
        code, cancelled, out = self.cancel(runs, env={"EVENT_NAME": "merge_group"})
        self.assertEqual((code, cancelled), (0, []), out)

    def test_an_event_that_is_neither_a_pull_request_nor_the_queue_cancels_nothing_not_even_its_own_run(self):
        for event in ("push", "schedule", "workflow_dispatch", "pull_request_target", ""):
            code, cancelled, out = self.cancel([run(2, ".github/workflows/e2e.yml")], env={"EVENT_NAME": event, "CANCEL_OWN": "true"})
            self.assertEqual((code, cancelled), (0, []), event)
            self.assertIn("nothing is cancelled", out)

    def test_a_pull_request_without_a_head_still_cancels_its_own_run_and_a_refused_cancellation_is_a_warning(self):
        code, cancelled, out = self.cancel([run(2, ".github/workflows/e2e.yml")], env={"CANCEL_OWN": "true", "HEAD_SHA": "", "HEAD_BRANCH": ""})
        self.assertEqual((code, cancelled), (0, ["1"]), out)
        code, cancelled, out = self.cancel([], env={"CANCEL_OWN": "true"}, CANCEL_FAIL=1)
        self.assertEqual(code, 0)
        self.assertIn("this run (1) could not be cancelled", out)

    def test_no_variable_of_the_environment_widens_what_it_cancels_or_loosens_who_it_cancels(self):
        """What the script may cancel is written in the script. An environment that offers more changes nothing."""
        runs = [run(2, ".github/workflows/release.yml"), run(3, ".github/workflows/codeql.yml"), run(4, ".github/workflows/e2e.yml", event="push"),
                run(5, ".github/workflows/e2e.yml", branch="other"), run(6, ".github/workflows/e2e.yml", repo="fork/r"), run(7, ".github/workflows/e2e.yml", sha=OTHER_SHA)]
        widening = {"CANCELLABLE_EXTRA": ".github/workflows/release.yml .github/workflows/codeql.yml", "CANCELLABLE": ".github/workflows/release.yml",
                    "EXTRA": "release.yml", "CANCEL_ALL": "true", "ALLOW_EVENTS": "push", "BRANCH_ANY": "true", "CANCEL_OWN_ONLY": "false"}
        code, cancelled, out = self.cancel(runs, env=widening)
        self.assertEqual((code, cancelled), (0, []), out)
        text = SCRIPT.read_text()
        for word in ("EXTRA", "bypass", "override"):
            self.assertNotIn(word, text)
        self.assertEqual(sorted(set(re.findall(r"\$\{([A-Z_]+)(?::-[^}]*)?\}", text))), ["CANCEL_OWN", "EVENT_NAME", "HEAD_BRANCH", "HEAD_SHA", "PR_NUMBER", "REPO", "RUN_ID"])

    def test_a_pull_request_with_no_head_branch_or_with_another_one_cancels_no_other_run_at_the_same_commit(self):
        runs = [run(2, ".github/workflows/e2e.yml", branch="feature"), run(3, ".github/workflows/db.yml", branch="someone-elses")]
        for branch in ("", "someone-elses-too", "feature/../x"):
            code, cancelled, out = self.cancel(runs, env={"HEAD_BRANCH": branch})
            self.assertEqual((code, cancelled), (0, []), branch)

    def test_a_run_of_another_pull_request_from_the_same_branch_at_the_same_commit_is_kept(self):
        """The same commit can head two pull requests, towards two bases: one failing does not end the runs of the other."""
        runs = [run(2, ".github/workflows/e2e.yml", pr=9), run(3, ".github/workflows/db.yml", pr=10),
                {**run(4, ".github/workflows/upgrade.yml"), "pull_requests": [{"number": 10}, {"number": 9}]},
                {**run(5, ".github/workflows/ldap.yml"), "pull_requests": []}, {k: v for k, v in run(6, ".github/workflows/container.yml").items() if k != "pull_requests"}]
        code, cancelled, out = self.cancel(runs)
        self.assertEqual((code, cancelled), (0, ["2", "4"]), out)
        for number in ("", "9x", "-9", "09; true", "nine"):
            code, cancelled, out = self.cancel(runs, env={"PR_NUMBER": number})
            self.assertEqual((code, cancelled), (0, []), number)

    def test_the_list_holds_only_workflows_that_exist_on_pull_requests_and_none_that_analyses_security(self):
        text = SCRIPT.read_text()
        block = text[text.index("CANCELLABLE=("):text.index("\n)\n", text.index("CANCELLABLE=("))]
        listed = re.findall(r"\.github/workflows/[\w.-]+\.yml", block)
        self.assertGreaterEqual(len(listed), 8)
        for path in listed:
            workflow = ci_yaml.load(ROOT / path)
            self.assertIn("pull_request", workflow[True], path)
            for word in ("codeql", "audit", "dco", "secret", "security", "release", "editorconfig", "guard", "mutants", "sign", "supply"):
                self.assertNotIn(word, path, path)
        self.assertEqual(len(listed), len(set(listed)))


def jobs_of(name):
    return ci_yaml.load(ROOT / ".github/workflows" / name)["jobs"]


class TheWiring(unittest.TestCase):
    def test_the_reusable_holds_the_write_token_in_one_job_and_does_nothing_else(self):
        workflow = ci_yaml.load(ROOT / ".github/workflows" / REUSABLE)
        self.assertEqual(workflow["permissions"], {})
        self.assertEqual(list(workflow["jobs"]), ["cancel"])
        job = workflow["jobs"]["cancel"]
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "write"})
        self.assertEqual(job["if"], "github.event_name == 'pull_request' || github.event_name == 'merge_group'")
        self.assertEqual(job["runs-on"], "ubuntu-latest", "the job with a write token runs on GitHub's runners, never on a variable pool")
        self.assertEqual(len(job["steps"]), 2)
        checkout, launch = job["steps"]
        self.assertRegex(checkout["uses"], r"^actions/checkout@[0-9a-f]{40}$")
        self.assertEqual(checkout["with"], {"persist-credentials": False, "fetch-depth": 2})
        self.assertEqual(set(launch["env"]), {"GH_TOKEN", "REPO", "RUN_ID", "EVENT_NAME", "CANCEL_OWN", "HEAD_SHA", "HEAD_BRANCH", "PR_NUMBER", "BASE_SHA"})
        self.assertEqual(launch["env"]["BASE_SHA"], "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha }}")
        self.assertIs(workflow[True]["workflow_call"]["inputs"]["cancel-own"]["default"], False)
        self.assertNotIn("${{", launch["run"], "the values of the event reach the step through env")
        self.assertIn('git show "${BASE_SHA}:.github/scripts/ci/cancel-others.sh" >"$RUNNER_TEMP/others.sh"', launch["run"])
        self.assertIn('bash "$RUNNER_TEMP/others.sh"', launch["run"])
        self.assertEqual(launch["run"].count("bash "), 1)
        self.assertIn("the base commit has no cancel script; nothing is cancelled", launch["run"])
        self.assertNotIn("bash scripts", launch["run"])

    def test_nothing_else_holds_actions_write_by_any_spelling_and_nothing_at_the_top_of_a_workflow(self):
        holders = {}
        for path in ci_yaml.workflow_files(ROOT):
            workflow = ci_yaml.load(path)
            top = workflow.get("permissions")
            self.assertFalse(self.holds(top), f"{path.name}: the permission belongs to one job, not to the workflow")
            for job_id, job in workflow["jobs"].items():
                perms = job["permissions"] if "permissions" in job else top
                if self.holds(perms):
                    holders[(path.name, job_id)] = job
        self.assertEqual({k for k in holders if k[0] != REUSABLE}, {(f, "cancel-others") for f in CALLERS} | {("ci.yml", "cancel-first-failure"), ("ci.yml", "cancel-on-package-failure")})
        self.assertIn((REUSABLE, "cancel"), holders)
        for (name, job_id), job in holders.items():
            if name != REUSABLE:
                self.assertEqual(job["uses"], f"./.github/workflows/{REUSABLE}", (name, job_id))
                self.assertNotIn("steps", job)

    @staticmethod
    def holds(perms):
        return perms == "write-all" or (isinstance(perms, dict) and perms.get("actions") == "write")

    def test_every_caller_runs_only_when_something_of_its_workflow_failed_on_a_pull_request(self):
        for name in CALLERS:
            jobs = jobs_of(name)
            job = jobs["cancel-others"]
            self.assertEqual(job["if"], "${{ failure() && github.event_name == 'pull_request' }}", name)
            self.assertEqual(job["permissions"], {"contents": "read", "actions": "write"}, name)
            self.assertTrue(job["needs"], name)
            for need in job["needs"]:
                self.assertIn(need, jobs, (name, need))
                self.assertNotEqual(need, "cancel-others")

    def test_the_first_failure_caller_waits_for_the_quick_jobs_only_and_cancels_the_run_it_is_in(self):
        jobs = jobs_of("ci.yml")
        job = jobs["cancel-first-failure"]
        self.assertEqual(job["if"], "${{ failure() && (github.event_name == 'pull_request' || github.event_name == 'merge_group') }}")
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "write"})
        self.assertEqual(job["with"], {"cancel-own": True})
        self.assertEqual(job["uses"], f"./.github/workflows/{REUSABLE}")
        # The point of it: it does not wait for what takes an hour.
        for long in ("rust", "debian", "deprecations", "gate", "cancel-others"):
            self.assertNotIn(long, job["needs"], long)
        self.assertGreaterEqual(set(job["needs"]), {"line-limit", "folder-limit", "python-tests", "secret-scan-tests", "audit"})
        for need in job["needs"]:
            self.assertIn(need, jobs, need)
        # And no other caller cancels its own run: it would end the jobs that are still to report.
        for name in CALLERS:
            for job_id, other in jobs_of(name).items():
                if job_id not in ("cancel-first-failure", "cancel-on-package-failure") and other.get("uses") == f"./.github/workflows/{REUSABLE}":
                    self.assertNotIn("with", other, (name, job_id))

    def test_the_package_failure_caller_waits_for_the_package_and_cancels_its_own_run(self):
        """The failure of the package build ends this run and the other runs of the commit without waiting for the long suite."""
        jobs = jobs_of("ci.yml")
        self.assertIn("cancel-on-package-failure", jobs)
        job = jobs["cancel-on-package-failure"]
        self.assertEqual(job["needs"], ["debian"])
        self.assertEqual(job["if"], "${{ failure() && (github.event_name == 'pull_request' || github.event_name == 'merge_group') }}")
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "write"})
        self.assertEqual(job["uses"], f"./.github/workflows/{REUSABLE}")
        self.assertEqual(job["with"], {"cancel-own": True})

    def test_a_workflow_a_failure_may_not_cancel_has_no_such_caller(self):
        for path in ci_yaml.workflow_files(ROOT):
            if path.name in CALLERS or path.name == REUSABLE:
                continue
            for job_id, job in ci_yaml.load(path)["jobs"].items():
                self.assertNotEqual(job.get("uses"), f"./.github/workflows/{REUSABLE}", (path.name, job_id))

    def test_the_script_is_run_from_the_base_and_is_executable_in_git(self):
        listed = subprocess.run(["git", "ls-files", "-s", "--", ".github/scripts/ci/cancel-others.sh"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        self.assertTrue(listed.startswith("100755"), listed)


PUBLISHING_SCOPES = ("id-token", "attestations", "packages", "deployments", "pages", "security-events", "issues", "pull-requests", "statuses", "checks", "discussions")


def writes(perms):
    """The scopes a `permissions` value grants write on, `write-all` as every one of them."""
    if perms == "write-all":
        return set(PUBLISHING_SCOPES) | {"contents"}
    if isinstance(perms, dict):
        return {scope for scope, level in perms.items() if level == "write" and scope != "actions"}
    return set()


def cancellable():
    text = SCRIPT.read_text()
    block = text[text.index("CANCELLABLE=("):text.index("\n)\n", text.index("CANCELLABLE=("))]
    return re.findall(r"\.github/workflows/[\w.-]+\.yml", block)


def walk(path, seen=()):
    """Every job of a workflow and, for a job that calls a local reusable, the jobs of that one, with the permissions each runs with."""
    workflow = ci_yaml.load(ROOT / path)
    top = workflow.get("permissions")
    for job_id, job in workflow["jobs"].items():
        perms = job["permissions"] if "permissions" in job else top
        yield path, job_id, job, perms
        target = job.get("uses", "")
        if target.startswith("./.github/workflows/") and target[2:] not in seen:
            yield from walk(target[2:], (*seen, path))


class WhatIsCancelledCannotPass(unittest.TestCase):
    """A run that is cancelled half way is a run that did not finish, and nothing may read it as one that passed."""

    def test_nothing_that_can_be_cancelled_publishes_signs_or_holds_an_environment(self):
        for path in cancellable():
            for where, job_id, job, perms in walk(path):
                if job_id == "cancel-others" or where.endswith(REUSABLE):
                    continue
                self.assertEqual(writes(perms), set(), f"{where}: {job_id} writes and can be cancelled half way")
                self.assertNotIn("environment", job, f"{where}: {job_id} holds an environment and can be cancelled half way")
                for step in job.get("steps", []):
                    self.assertNotRegex(str(step.get("uses", "")) + str(step.get("run", "")), r"gh release (create|upload|edit|delete)|attest-build-provenance|podman push|git push|cosign|sign_release",
                                        f"{where}: {job_id} publishes and can be cancelled half way")

    def test_only_ci_yml_of_the_workflows_it_can_cancel_runs_in_the_queue_and_none_is_scheduled_or_a_release(self):
        for path in cancellable():
            on = ci_yaml.load(ROOT / path)[True]
            if path != ".github/workflows/ci.yml":
                self.assertNotIn("merge_group", on, path)
            self.assertNotIn("push", {k for k in on if k == "push" and path.endswith("release.yml")}, path)
            self.assertNotIn("tags", str((on.get("push") or {})), path)

    def test_every_job_of_ci_yml_that_is_cancelled_is_waited_for_by_the_gate_and_a_cancellation_turns_it_red(self):
        from ci_gate import test_ci_gate as gate

        jobs = ci_yaml.load(ROOT / ".github/workflows/ci.yml")["jobs"]
        waited = set(jobs["gate"]["needs"])
        exempt = {"plan", "gate", "dependabot-freshness", "cancel-others", "cancel-first-failure", "cancel-on-package-failure"}
        self.assertEqual(set(jobs) - exempt - waited, set(), "a job of ci.yml the gate does not wait for can be cancelled and the run still green")
        self.assertEqual(jobs["gate"]["if"], "always()")
        for suite in gate.SUITES:
            with self.subTest(suite=suite):
                code, out = gate.run_gate(gate.needs(**{suite: "cancelled"}))
                self.assertEqual(code, 1, out)
                self.assertIn(f"{suite} did not succeed (result: cancelled)", out)

    def test_a_job_the_gate_waits_for_runs_with_no_condition_that_a_cancellation_could_turn_into_a_skip(self):
        jobs = ci_yaml.load(ROOT / ".github/workflows/ci.yml")["jobs"]
        for name in jobs["gate"]["needs"]:
            if name == "plan":
                continue
            condition = str(jobs[name].get("if", ""))
            self.assertTrue(condition.startswith("${{ !cancelled()") or condition == "always()", f"{name}: {condition}")


if __name__ == "__main__":
    unittest.main()
