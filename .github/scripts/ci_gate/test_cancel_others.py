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


def run(number, path, event="pull_request", sha=SHA, branch="feature", repo=REPO, status="in_progress"):
    return {"id": number, "event": event, "head_sha": sha, "head_branch": branch, "status": status, "path": path,
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
        values = {"GH_TOKEN": "t", "REPO": REPO, "RUN_ID": own, "HEAD_SHA": SHA, "HEAD_BRANCH": "feature", **(env or {})}
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
        for missing in ("REPO", "RUN_ID", "HEAD_SHA", "HEAD_BRANCH"):
            code, cancelled, out = self.cancel([run(2, ".github/workflows/e2e.yml")], env={missing: ""})
            self.assertEqual((code, cancelled), (0, []), missing)
            self.assertIn("nothing is cancelled", out)

    def test_inputs_that_are_not_what_they_claim_to_be_cancel_nothing(self):
        for env in ({"HEAD_SHA": "main"}, {"HEAD_SHA": f"{SHA}; true"}, {"RUN_ID": "1; echo"}):
            code, cancelled, out = self.cancel([run(2, ".github/workflows/e2e.yml")], env=env)
            self.assertEqual((code, cancelled), (0, []), env)

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
        self.assertEqual(job["if"], "github.event_name == 'pull_request'")
        self.assertEqual(job["runs-on"], "ubuntu-latest", "the job with a write token runs on GitHub's runners, never on a variable pool")
        self.assertEqual(len(job["steps"]), 2)
        checkout, launch = job["steps"]
        self.assertRegex(checkout["uses"], r"^actions/checkout@[0-9a-f]{40}$")
        self.assertEqual(checkout["with"], {"persist-credentials": False, "fetch-depth": 2})
        self.assertEqual(set(launch["env"]), {"GH_TOKEN", "REPO", "RUN_ID", "HEAD_SHA", "HEAD_BRANCH", "BASE_SHA"})
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
        self.assertEqual({k for k in holders if k[0] != REUSABLE}, {(f, "cancel-others") for f in CALLERS})
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
        exempt = {"plan", "gate", "dependabot-freshness", "cancel-others"}
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
