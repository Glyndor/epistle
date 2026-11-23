"""The script that cancels the other runs of a commit, run against a fake `gh`."""

import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SCRIPT = HERE / "others.sh"

FAKE_GH = """#!/usr/bin/env bash
# Records every call. `api -X GET .../runs` answers with $FAKE_RUNS; a cancel
# fails when its run id is in $FAKE_REFUSE; $FAKE_LIST_FAILS makes the list fail.
echo "$*" >> "$FAKE_LOG"
case "$*" in
  *"-X GET"*)
    [ -n "${FAKE_LIST_FAILS:-}" ] && exit 1
    jq -c '.workflow_runs' "$FAKE_RUNS" ;;
  *"-X POST"*)
    id="$(printf '%s' "$*" | sed -E 's#.*/runs/([0-9]+)/cancel.*#\\1#')"
    case " ${FAKE_REFUSE:-} " in *" $id "*) exit 1 ;; esac ;;
esac
"""

SHA, REF, PR, SELF = "a" * 40, "topic", 7, 100


def run(**overrides):
    return {"id": 1, "name": "E2E", "event": "pull_request", "status": "in_progress",
            "head_sha": SHA, "head_branch": REF, "pull_requests": [{"number": PR}], **overrides}


class Others(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        gh = self.dir / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
        self.log = self.dir / "calls.log"
        self.log.write_text("")

    def go(self, runs, refuse="", list_fails=False, **env):
        (self.dir / "runs.json").write_text(json.dumps({"workflow_runs": runs}))
        done = subprocess.run(
            ["bash", str(SCRIPT)],
            env={**os.environ, "PATH": f"{self.dir}:{os.environ['PATH']}", "FAKE_LOG": str(self.log),
                 "FAKE_RUNS": str(self.dir / "runs.json"), "FAKE_REFUSE": refuse,
                 "FAKE_LIST_FAILS": "1" if list_fails else "",
                 "GH_TOKEN": "t", "REPO": "o/r", "PR_NUMBER": str(PR), "HEAD_REF": REF,
                 "HEAD_SHA": SHA, "RUN_ID": str(SELF), **env},
            capture_output=True, text=True, check=False)
        cancelled = re.findall(r"runs/(\d+)/cancel", self.log.read_text())
        return done, [int(i) for i in cancelled]

    def test_it_cancels_a_listed_workflow_of_the_same_pull_request_and_commit(self):
        done, cancelled = self.go([run(id=1), run(id=2, name="Database", status="queued")])
        self.assertEqual((done.returncode, cancelled), (0, [1, 2]), done.stderr)

    def test_it_does_not_cancel_a_push_or_a_queue_entry_of_the_same_commit(self):
        for event in ("push", "merge_group", "schedule", "workflow_dispatch", "release"):
            with self.subTest(event=event):
                self.assertEqual(self.go([run(event=event)])[1], [])

    def test_it_does_not_cancel_its_own_run(self):
        self.assertEqual(self.go([run(id=SELF)])[1], [])

    def test_it_does_not_cancel_a_workflow_outside_the_list(self):
        for name in ("CodeQL", "Rust audit", "DCO", "Release", "CI", "Dependabot security watch", "e2e"):
            with self.subTest(name=name):
                self.assertEqual(self.go([run(name=name)])[1], [])

    def test_it_does_not_cancel_another_commit_branch_or_pull_request(self):
        self.assertEqual(self.go([run(head_sha="b" * 40)])[1], [])
        self.assertEqual(self.go([run(head_branch="other")])[1], [])
        self.assertEqual(self.go([run(pull_requests=[{"number": 8}])])[1], [])
        self.assertEqual(self.go([run(pull_requests=[])])[1], [])

    def test_it_does_not_touch_a_run_that_is_over(self):
        self.assertEqual(self.go([run(status="completed")])[1], [])

    def test_it_does_not_fail_when_it_cannot_list(self):
        done, cancelled = self.go([run()], list_fails=True)
        self.assertEqual((done.returncode, cancelled), (0, []))
        self.assertIn("could not list", done.stdout)

    def test_it_does_not_fail_when_a_cancel_is_refused_and_goes_on(self):
        done, cancelled = self.go([run(id=1), run(id=2)], refuse="1")
        self.assertEqual((done.returncode, cancelled), (0, [1, 2]))
        self.assertIn("could not cancel run 1", done.stdout)

    def test_it_does_nothing_when_the_environment_is_incomplete(self):
        for name in ("GH_TOKEN", "REPO", "PR_NUMBER", "HEAD_REF", "HEAD_SHA", "RUN_ID"):
            with self.subTest(name=name):
                done, cancelled = self.go([run()], **{name: ""})
                self.assertEqual((done.returncode, cancelled), (0, []))

    def test_it_ignores_a_list_that_is_not_json(self):
        (self.dir / "runs.json").write_text("{}")
        done, cancelled = self.go([])
        self.assertEqual((done.returncode, cancelled), (0, []))

    def test_a_run_id_that_is_not_a_number_is_never_passed_to_gh(self):
        self.assertEqual(self.go([run(id="1; rm -rf /")])[1], [])
        self.assertNotIn("rm -rf", self.log.read_text())


if __name__ == "__main__":
    unittest.main()
