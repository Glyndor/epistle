"""Every job name that carries an expression is one this file knows, and the required ones vary by event.

A job skipped by its `if` still emits its name, and GitHub counts a skipped job
as passed; so a workflow that runs on several events must not emit the name a
ruleset requires on an event the ruleset does not mean.
"""

import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]

# Every job `name:` with an expression in the tree, exactly as written. A new one
# fails the test until someone lists it here and says what it resolves to.
KNOWN = {
    ("codeql.yml", "analyze"): "Analyze (${{ matrix.language }})",  # actions, rust
    ("db.yml", "db-tests"): "database integration (PostgreSQL ${{ matrix.postgres }})",  # 18
    ("fuzz.yml", "fuzz"): "cargo fuzz (group ${{ matrix.group.id }})",  # 1 to 5
    ("e2e.yml", "e2e"): "full-server e2e (${{ matrix.os }})",  # ubuntu-22.04, ubuntu-24.04
    ("release.yml", "build-deb"): "Build Debian package (${{ matrix.arch }})",
    ("release.yml", "image-build"): "Build and push image (${{ matrix.arch }})",
    ("reusable-rust-audit.yml", "audit"): "cargo audit${{ inputs.ref != '' && format(' ({0})', inputs.ref) || '' }}",
    ("reusable-rust-audit.yml", "deny"): "cargo deny${{ inputs.ref != '' && format(' ({0})', inputs.ref) || '' }}",
    ("reusable-rust-ci.yml", "test-extra"): "Test (${{ matrix.os }})",
    ("reusable-rust-ci.yml", "msrv"): "MSRV (${{ inputs.msrv }})",
    ("ci.yml", "gate"): (
        "${{ github.event_name == 'merge_group' && 'CI gate' || github.event_name == 'pull_request'"
        " && (github.event.pull_request.base.ref == 'main' && 'CI gate (main)' || 'CI gate')"
        " || format('CI gate ({0})', github.event_name) }}"
    ),
}
# Required on develop and emitted by a workflow that only runs on these events.
ONLY_PR_AND_QUEUE = {"dco.yml"}


def names():
    for path in ci_yaml.workflow_files(ROOT):
        for job_id, job in ci_yaml.load(path)["jobs"].items():
            yield path.name, job_id, job, ci_yaml.load(path)


class JobNames(unittest.TestCase):
    def test_every_name_with_an_expression_is_listed_exactly(self):
        found = {(f, j): job["name"] for f, j, job, _ in names() if "${{" in str(job.get("name", ""))}
        self.assertEqual(found, KNOWN)

    def test_the_workflows_that_emit_a_required_name_without_the_event_run_on_pull_requests_and_the_queue_only(self):
        for name in ONLY_PR_AND_QUEUE:
            on = ci_yaml.load(ROOT / ".github/workflows" / name)[True]
            self.assertEqual(set(on), {"pull_request", "merge_group"}, name)

    def test_a_workflow_with_more_events_names_its_required_job_by_event(self):
        ci = ci_yaml.load(ROOT / ".github/workflows/ci.yml")
        self.assertGreater(len(ci[True]), 2)
        self.assertIn("github.event_name", ci["jobs"]["gate"]["name"])
        self.assertIn("github.event.pull_request.base.ref", ci["jobs"]["gate"]["name"])

    def test_matrix_names_name_a_matrix_that_exists(self):
        for filename, job_id, job, workflow in names():
            if "matrix." in str(job.get("name", "")):
                self.assertIn("matrix", job.get("strategy", {}), (filename, job_id))


if __name__ == "__main__":
    unittest.main()
