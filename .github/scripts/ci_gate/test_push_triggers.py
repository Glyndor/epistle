"""A commit is not run twice: a workflow that the merge queue runs never also runs on the push to develop that follows.

The queue entry is the tree that lands on develop, so a workflow that is in the queue and on `push` to develop
checks the same commit a second time. The workflows that push to develop and are not in the queue are a closed
list, each with the reason its run on the landed commit is the only one on the merged tree.
"""

import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
NOT_IN_THE_QUEUE = "not in the merge queue: the run on the landed commit is the only one on the merged tree"
PUSHES_TO_DEVELOP = {
    "bench.yml": "benchmarks of the landed commit, behind a path filter; no pull request run",
    "codeql.yml": "the alerts of develop come from the analysis of the landed commit; a pull request analysis only reports what its diff touches",
    "container.yml": NOT_IN_THE_QUEUE,
    "db.yml": NOT_IN_THE_QUEUE,
    "dependabot-security-watch.yml": "reads the open Dependabot alerts of develop; not a check of a commit",
    "e2e.yml": NOT_IN_THE_QUEUE,
    "editorconfig.yml": NOT_IN_THE_QUEUE,
    "imaptest.yml": NOT_IN_THE_QUEUE,
    "interop.yml": NOT_IN_THE_QUEUE,
    "ldap.yml": NOT_IN_THE_QUEUE,
    "upgrade.yml": NOT_IN_THE_QUEUE,
}


def events(path):
    on = ci_yaml.load(path)[True]
    return on if isinstance(on, dict) else {name: None for name in (on if isinstance(on, list) else [on])}


def pushes_to_develop(push):
    """True when a `push` trigger reaches the branch `develop`; anything it cannot read counts as reaching it."""
    if push is None:
        return True
    if not isinstance(push, dict):
        return True
    if "tags" in push and "branches" not in push and "branches-ignore" not in push:
        return False
    branches = push.get("branches")
    ignored = push.get("branches-ignore")
    if branches is not None:
        if not isinstance(branches, list):
            return True
        return any(b == "develop" or b == "**" or b == "*" or b.startswith("d") and "*" in b for b in branches)
    if ignored is not None:
        return not (isinstance(ignored, list) and "develop" in ignored)
    return True


class PushTriggers(unittest.TestCase):
    def test_a_workflow_in_the_queue_does_not_also_run_on_a_push_to_develop(self):
        for path in ci_yaml.workflow_files(ROOT):
            on = events(path)
            if "merge_group" in on and "push" in on:
                self.assertFalse(pushes_to_develop(on["push"]), f"{path.name} runs twice on the commit that lands")

    def test_the_workflows_that_push_to_develop_are_exactly_the_listed_ones(self):
        found = {path.name for path in ci_yaml.workflow_files(ROOT) if "push" in events(path) and pushes_to_develop(events(path)["push"])}
        self.assertEqual(found, set(PUSHES_TO_DEVELOP), "a workflow that pushes to develop is listed here with its reason, or does not")
        for name, reason in PUSHES_TO_DEVELOP.items():
            self.assertGreater(len(reason), 30, name)
            self.assertNotIn("merge_group", events(ROOT / ".github/workflows" / name), f"{name} is in the queue")

    def test_the_audit_is_the_queues_and_the_daily_run_and_not_a_push(self):
        self.assertEqual(set(events(ROOT / ".github/workflows/rust-audit.yml")), {"schedule", "workflow_dispatch"})
        ci = ci_yaml.load(ROOT / ".github/workflows/ci.yml")["jobs"]
        self.assertEqual(ci["audit"]["uses"], "./.github/workflows/reusable-rust-audit.yml")
        self.assertIn("merge_group", events(ROOT / ".github/workflows/ci.yml"))


class TheReader(unittest.TestCase):
    """Each way a push can reach develop, and the ones that cannot."""

    def test_what_reaches_develop_and_what_does_not(self):
        reaches = [None, {}, {"branches": ["main", "develop"]}, {"branches": ["**"]}, {"branches": "develop"},
                   {"branches-ignore": ["main"]}, {"branches": ["dev*"]}, "develop"]
        for push in reaches:
            self.assertTrue(pushes_to_develop(push), push)
        stays = [{"branches": ["main"]}, {"tags": ["v*"]}, {"branches": ["main"], "tags": ["v*"]},
                 {"branches": ["release/**"]}, {"branches-ignore": ["develop"]}]
        for push in stays:
            self.assertFalse(pushes_to_develop(push), push)


if __name__ == "__main__":
    unittest.main()
