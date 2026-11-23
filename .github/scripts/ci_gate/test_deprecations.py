"""The job that fails on a deprecation annotation, run against a fake `gh`."""

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
FAKE_GH = """#!/usr/bin/env bash
# `gh api --paginate PATH`: the jobs of the run, or the annotations of a job,
# each as the files in $FAKE_DIR hold them (one JSON document per page).
echo "$*" >> "$FAKE_DIR/calls.log"
[ -n "${FAKE_FAIL:-}" ] && { echo "boom" >&2; exit 1; }
path="${3%%\\?*}"
case "$path" in
  */jobs) cat "$FAKE_DIR/jobs.json" ;;
  */annotations) id="$(basename "$(dirname "$path")")"; cat "$FAKE_DIR/annotations-$id.json" 2> /dev/null || echo '[]' ;;
esac
"""


def step():
    job = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]["deprecations"]
    return job["steps"][0]["run"]


class Deprecations(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        gh = self.dir / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(gh.stat().st_mode | stat.S_IEXEC)

    def run_step(self, jobs, notes=None, fail=False):
        pages = "".join(json.dumps({"jobs": page}) for page in jobs)
        (self.dir / "jobs.json").write_text(pages)
        for job_id, page_list in (notes or {}).items():
            (self.dir / f"annotations-{job_id}.json").write_text("".join(json.dumps(p) for p in page_list))
        done = subprocess.run(
            ["bash", "-e", "-c", step()],
            env={**os.environ, "PATH": f"{self.dir}:{os.environ['PATH']}", "FAKE_DIR": str(self.dir),
                 "FAKE_FAIL": "1" if fail else "", "GH_TOKEN": "t", "REPO": "o/r", "RUN_ID": "9"},
            capture_output=True, text=True, check=False)
        return done.returncode, done.stdout + done.stderr

    def test_a_run_without_annotations_passes(self):
        code, out = self.run_step([[{"id": 1, "name": "lint"}]])
        self.assertEqual(code, 0, out)
        self.assertIn("No deprecation notice in 1 jobs", out)

    def test_a_deprecation_warning_fails_and_names_the_job(self):
        note = {"annotation_level": "warning", "message": "Node.js 20 actions are deprecated.\nUse v5."}
        code, out = self.run_step([[{"id": 1, "name": "lint"}, {"id": 2, "name": "wiring tests"}]], {2: [[note]]})
        self.assertEqual(code, 1)
        self.assertIn("::error::wiring tests: Node.js 20 actions are deprecated.", out)

    def test_it_reads_every_page_of_jobs_and_of_annotations(self):
        note = {"annotation_level": "failure", "message": "The set-output command is deprecated"}
        code, out = self.run_step([[{"id": 1, "name": "a"}], [{"id": 2, "name": "b"}]], {2: [[], [note]]})
        self.assertEqual(code, 1)
        self.assertIn("b: The set-output command is deprecated", out)

    def test_other_warnings_and_plain_notices_do_not_fail(self):
        notes = [[{"annotation_level": "warning", "message": "soft limit reached"},
                  {"annotation_level": "notice", "message": "deprecated but only a notice"}]]
        self.assertEqual(self.run_step([[{"id": 1, "name": "a"}]], {1: notes})[0], 0)

    def test_a_message_with_braces_does_not_break_the_page_reading(self):
        note = {"annotation_level": "warning", "message": "x}{[ deprecated ]}{y"}
        code, out = self.run_step([[{"id": 1, "name": "a"}]], {1: [[note]]})
        self.assertEqual(code, 1)
        self.assertIn("deprecated", out)

    def test_it_fails_closed_when_the_api_cannot_be_read(self):
        code, out = self.run_step([[{"id": 1, "name": "a"}]], fail=True)
        self.assertEqual(code, 1)
        self.assertIn("could not read", out)

    def test_the_job_holds_only_read_scopes_and_runs_on_every_event(self):
        job = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]["deprecations"]
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "read", "checks": "read"})
        self.assertEqual(job["if"], "always()")
        self.assertNotIn("${{", job["steps"][0]["run"])


if __name__ == "__main__":
    unittest.main()
