"""What has to hold for the checks that guard identity, secrets and the promotion into main."""

import os
import subprocess
import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github/workflows"
# The names of the checks the rulesets require, besides the gate.
REQUIRED = {
    "dco / Signed-off-by present on every commit",
    "author and sign-off use a GitHub noreply address",
    "no credential-shaped line is added",
    "develop-only / develop-only",
}


def load(name):
    return ci_yaml.load(WORKFLOWS / name)


class DevelopOnly(unittest.TestCase):
    def step(self):
        return load("reusable-main-guard.yml")["jobs"]["develop-only"]["steps"][0]["run"]

    def run_step(self, head_ref, head_repo, base_repo="Glyndor/epistle"):
        done = subprocess.run(["bash", "-e", "-c", self.step()], capture_output=True, text=True, check=False,
                              env={**os.environ, "HEAD_REF": head_ref, "HEAD_REPO": head_repo, "BASE_REPO": base_repo})
        return done.returncode, done.stdout + done.stderr

    def test_a_develop_branch_of_this_repository_passes(self):
        self.assertEqual(self.run_step("develop", "Glyndor/epistle")[0], 0)

    def test_a_develop_branch_of_a_fork_does_not(self):
        code, out = self.run_step("develop", "someone/epistle")
        self.assertEqual(code, 1, out)
        self.assertIn("someone/epistle", out)

    def test_another_branch_or_another_case_of_the_name_does_not(self):
        for ref in ("feature", "Develop", "DEVELOP", "develop-2", "refs/heads/develop", ""):
            with self.subTest(ref=ref):
                self.assertEqual(self.run_step(ref, "Glyndor/epistle")[0], 1)

    def test_the_repository_is_compared_exactly_and_not_by_case(self):
        self.assertEqual(self.run_step("develop", "glyndor/epistle")[0], 1)

    def test_the_job_reads_the_repository_from_the_event_and_runs_only_for_main(self):
        job = load("reusable-main-guard.yml")["jobs"]["develop-only"]
        env = job["steps"][0]["env"]
        self.assertEqual(env, {"HEAD_REF": "${{ github.head_ref }}",
                               "HEAD_REPO": "${{ github.event.pull_request.head.repo.full_name }}",
                               "BASE_REPO": "${{ github.repository }}"})
        self.assertEqual(job["if"], "github.event_name == 'pull_request' && github.event.pull_request.base.ref == 'main'")
        caller = load("main-guard.yml")
        self.assertEqual(caller[True], {"pull_request": {"branches": ["main"]}})
        self.assertEqual(caller["jobs"]["develop-only"]["uses"], "./.github/workflows/reusable-main-guard.yml")


class SecurityResultsCount(unittest.TestCase):
    def test_identity_and_secret_scan_run_in_every_pull_request_and_queue_entry_and_cannot_be_skipped(self):
        workflow = load("dco.yml")
        self.assertEqual(set(workflow[True]), {"pull_request", "merge_group"})
        self.assertIsNone(workflow[True]["pull_request"])
        for job_id in ("dco", "noreply", "secret-scan"):
            job = workflow["jobs"][job_id]
            for key in ("if", "needs", "continue-on-error", "strategy"):
                self.assertNotIn(key, job, job_id)
            for step in job.get("steps", []):
                for key in ("if", "continue-on-error"):
                    self.assertNotIn(key, step, job_id)

    def test_the_names_the_rulesets_require_are_the_ones_these_jobs_emit(self):
        workflow = load("dco.yml")["jobs"]
        self.assertEqual(workflow["noreply"]["name"], "author and sign-off use a GitHub noreply address")
        self.assertEqual(workflow["secret-scan"]["name"], "no credential-shaped line is added")

    def test_the_security_workflows_each_have_a_group_of_their_own(self):
        """Groups with `github.workflow` read as the workflow's name, which is what the runner makes of them."""
        groups = {}
        for name in ("dco.yml", "codeql.yml", "rust-audit.yml"):
            workflow = load(name)
            group = workflow["concurrency"]["group"]
            self.assertIn("github.workflow", group, name)
            groups[name] = group.replace("${{ github.workflow }}", workflow["name"])
        # What a reusable adds inside the caller is a different group from the caller's own.
        groups["reusable-rust-audit.yml"] = load("reusable-rust-audit.yml")["concurrency"]["group"].replace(
            "${{ github.workflow }}", load("rust-audit.yml")["name"])
        groups["reusable-dco.yml"] = load("reusable-dco.yml")["concurrency"]["group"].replace(
            "${{ github.workflow }}", load("dco.yml")["name"])
        self.assertEqual(len(set(groups.values())), len(groups), groups)

    def test_the_scheduled_audit_by_branch_does_not_stop_at_the_first_failure(self):
        matrix = load("rust-audit.yml")["jobs"]["audit"]["strategy"]
        self.assertIs(matrix["fail-fast"], False)

    def test_the_gate_waits_for_the_audit_and_the_audit_is_never_skipped_by_a_plan(self):
        ci = load("ci.yml")["jobs"]
        self.assertIn("audit", ci["gate"]["needs"])
        self.assertEqual(ci["audit"]["if"], "${{ !cancelled() }}")
        self.assertNotIn("needs", ci["audit"])


class NamesIgnoreCase(unittest.TestCase):
    def test_no_two_jobs_that_emit_a_required_name_differ_only_in_case(self):
        names = []
        for path in ci_yaml.workflow_files(ROOT):
            for job in ci_yaml.load(path)["jobs"].values():
                name = job.get("name")
                if isinstance(name, str) and "${{" not in name:
                    names.append(name)
        lowered = {}
        for name in names:
            lowered.setdefault(name.lower(), set()).add(name)
        for required in REQUIRED - {"dco / Signed-off-by present on every commit", "develop-only / develop-only"}:
            self.assertEqual(lowered.get(required.lower()), {required}, required)
        for name, spellings in lowered.items():
            if name.startswith("ci gate"):
                self.fail(f"a job outside the gate's own name expression is called {spellings}")


if __name__ == "__main__":
    unittest.main()
