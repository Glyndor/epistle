"""The job that cancels other runs holds a write token; these tests pin how it is wired.

Nothing a pull request writes may run with `actions: write`, the list of
workflows it can cancel holds no analysis, and the job cannot leave a pull
request green.
"""

import re
import unittest
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
WORKFLOWS = ROOT / ".github/workflows"
SCRIPT = (HERE / "others.sh").read_text()

# The only job allowed to hold `actions: write`, and the only things it may do.
ALLOWED_JOB = ("ci.yml", "cancel-others")
CHECKOUT = re.compile(r"actions/checkout@[0-9a-f]{40}( # v[0-9.]+)?")
LAUNCHER = """set -uo pipefail
script="$RUNNER_TEMP/others.sh"
if ! git show "${BASE_SHA}:.github/scripts/ci_cancel/others.sh" > "$script" 2> /dev/null; then
  echo "::warning::the base commit has no cancel script; nothing is cancelled"
  exit 0
fi
bash "$script"
"""
# Workflows whose name or file says analysis, audit, secret scan, identity or release.
PROTECTED_WORDS = ("codeql", "audit", "secret", "credential", "dco", "security", "release", "dependabot", "scan", "sign")


def load():
    out = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        out[path.name] = yaml.safe_load(path.read_text())
    return out


def effective(workflow, job):
    """The permissions a job really has: its own block, else the workflow's, else the default."""
    if "permissions" in job:
        return job["permissions"]
    return workflow.get("permissions", "default")


def can_write_actions(perms):
    if perms == "default" or perms == "write-all":
        return True  # the repository default may be write, and write-all is every scope
    return isinstance(perms, dict) and perms.get("actions") == "write"


class WriteToken(unittest.TestCase):
    def test_only_the_cancel_job_can_write_actions_and_nothing_else_inherits_it(self):
        found = []
        for name, workflow in load().items():
            for job_id, job in workflow["jobs"].items():
                if can_write_actions(effective(workflow, job)):
                    found.append((name, job_id))
        self.assertEqual(found, [ALLOWED_JOB])

    def test_write_all_counts_as_actions_write(self):
        self.assertTrue(can_write_actions("write-all"))
        self.assertTrue(can_write_actions("default"))
        self.assertTrue(can_write_actions({"actions": "write"}))
        self.assertFalse(can_write_actions({"actions": "read", "contents": "read"}))
        self.assertFalse(can_write_actions({}))

    def test_a_job_inherits_the_permissions_of_its_workflow(self):
        workflow = {"permissions": {"actions": "write"}}
        self.assertTrue(can_write_actions(effective(workflow, {})))
        self.assertFalse(can_write_actions(effective(workflow, {"permissions": {"contents": "read"}})))

    def test_the_job_holds_exactly_the_two_scopes_it_needs(self):
        job = load()[ALLOWED_JOB[0]]["jobs"][ALLOWED_JOB[1]]
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "write"})

    def test_the_workflow_that_holds_the_job_grants_nothing_at_the_top(self):
        workflow = load()["ci.yml"]
        self.assertEqual(workflow["permissions"], {"contents": "read"})

    def test_its_steps_are_the_pinned_checkout_and_the_known_launcher_and_nothing_else(self):
        job = load()[ALLOWED_JOB[0]]["jobs"][ALLOWED_JOB[1]]
        checkout, launcher = job["steps"]
        self.assertRegex(checkout["uses"], CHECKOUT)
        self.assertEqual(checkout["with"], {"persist-credentials": False, "fetch-depth": 2})
        self.assertNotIn("run", checkout)
        self.assertEqual(launcher["run"], LAUNCHER)
        self.assertNotIn("uses", launcher)
        self.assertNotIn("working-directory", launcher)
        self.assertNotIn("shell", launcher)

    def test_the_job_and_its_environment_run_nothing_from_the_tree(self):
        job = load()[ALLOWED_JOB[0]]["jobs"][ALLOWED_JOB[1]]
        for key in ("container", "services", "defaults", "env"):
            self.assertNotIn(key, job)
        self.assertEqual(job["runs-on"], "ubuntu-latest")

    def test_every_event_value_reaches_the_launcher_through_env(self):
        job = load()[ALLOWED_JOB[0]]["jobs"][ALLOWED_JOB[1]]
        for step in job["steps"]:
            self.assertNotIn("${{", step.get("run", ""))
        env = job["steps"][1]["env"]
        for name in ("PR_NUMBER", "HEAD_REF", "HEAD_SHA", "BASE_SHA", "RUN_ID"):
            self.assertIn("${{ ", env[name])

    def test_it_runs_on_pull_requests_of_this_repository_only(self):
        condition = load()[ALLOWED_JOB[0]]["jobs"][ALLOWED_JOB[1]]["if"]
        self.assertIn("github.event_name == 'pull_request'", condition)
        self.assertIn("head.repo.full_name == github.repository", condition)
        for event in ("push", "merge_group", "schedule", "workflow_dispatch"):
            self.assertNotIn(event, condition)

    def test_cancelling_cannot_turn_a_pull_request_green(self):
        jobs = load()["ci.yml"]["jobs"]
        self.assertNotIn(ALLOWED_JOB[1], jobs["gate"]["needs"])
        for job_id, job in jobs.items():
            needs = job.get("needs", [])
            needs = [needs] if isinstance(needs, str) else needs
            self.assertNotIn(ALLOWED_JOB[1], needs, job_id)


class WhatItMayCancel(unittest.TestCase):
    def listed(self):
        match = re.search(r"^CANCELABLE='(\[.*\])'$", SCRIPT, re.M)
        self.assertIsNotNone(match)
        return yaml.safe_load(match.group(1))

    def test_every_name_is_a_workflow_that_exists(self):
        names = {w["name"] for w in load().values()}
        for name in self.listed():
            self.assertIn(name, names)

    def test_no_analysis_audit_scan_identity_or_release_workflow_is_on_the_list(self):
        workflows = load()
        for file, workflow in workflows.items():
            words = f"{file} {workflow['name']}".lower()
            if any(word in words for word in PROTECTED_WORDS):
                self.assertNotIn(workflow["name"], self.listed(), file)

    def test_the_protected_words_do_catch_the_workflows_they_are_meant_for(self):
        for file in ("codeql.yml", "rust-audit.yml", "dco.yml", "release.yml", "dependabot-security-watch.yml"):
            workflow = load()[file]
            self.assertTrue(any(w in f"{file} {workflow['name']}".lower() for w in PROTECTED_WORDS), file)

    def test_no_listed_workflow_publishes_or_holds_a_secret_or_a_write_scope(self):
        workflows = {w["name"]: (f, w) for f, w in load().items()}
        for name in self.listed():
            file, workflow = workflows[name]
            text = (WORKFLOWS / file).read_text()
            self.assertNotIn("secrets.", text.replace("secrets.GITHUB_TOKEN", ""), file)
            for job in workflow["jobs"].values():
                perms = effective(workflow, job)
                self.assertFalse(isinstance(perms, dict) and "write" in perms.values(), file)

    def test_the_script_only_cancels_pull_request_runs_of_the_same_pull_request_branch_and_commit(self):
        for fragment in ('.event == "pull_request"', ".head_sha == $sha and .head_branch == $ref",
                         ".id != $self", ".number == $pr", "-f event=pull_request"):
            self.assertIn(fragment, SCRIPT)


if __name__ == "__main__":
    unittest.main()
