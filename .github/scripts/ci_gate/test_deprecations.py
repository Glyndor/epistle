"""The check of deprecation notices: the script against a fake `gh`, and how the workflow wires it."""

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / ".github/scripts/ci/no-deprecation-notices.sh"
REUSABLE = ROOT / ".github/workflows/reusable-deprecation-notices.yml"
FAKE_GH = """#!/usr/bin/env bash
# `gh api --paginate PATH`: the jobs of the run, or the annotations of a job, each as the
# files in $FAKE_DIR hold them (one JSON document per page). A path in $FAKE_FAIL_ON fails.
echo "$*" >> "$FAKE_DIR/calls.log"
path="${3%%\\?*}"
case "$path" in *"${FAKE_FAIL_ON:-@none@}"*) echo "boom" >&2; exit 1 ;; esac
case "$path" in
  */jobs) cat "$FAKE_DIR/jobs.json" ;;
  */annotations) id="$(basename "$(dirname "$path")")"; cat "$FAKE_DIR/annotations-$id.json" 2> /dev/null || echo '[]' ;;
esac
"""


class TheScript(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        gh = self.dir / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(gh.stat().st_mode | stat.S_IEXEC)

    def run_script(self, jobs, notes=None, fail_on="", run_id="9"):
        (self.dir / "jobs.json").write_text("".join(json.dumps({"jobs": page}) for page in jobs))
        for job_id, pages in (notes or {}).items():
            (self.dir / f"annotations-{job_id}.json").write_text("".join(json.dumps(p) for p in pages))
        done = subprocess.run(
            ["bash", str(SCRIPT)],
            env={**os.environ, "PATH": f"{self.dir}:{os.environ['PATH']}", "FAKE_DIR": str(self.dir),
                 "FAKE_FAIL_ON": fail_on or "@none@", "GH_TOKEN": "t", "REPO": "o/r", "RUN_ID": run_id},
            capture_output=True, text=True, check=False)
        return done.returncode, done.stdout + done.stderr

    def test_a_run_without_annotations_passes(self):
        code, out = self.run_script([[{"id": 1, "name": "lint"}]])
        self.assertEqual(code, 0, out)
        self.assertIn("no job of run 9 carries a deprecation warning", out)

    def test_a_deprecation_warning_fails_and_names_the_job(self):
        note = {"annotation_level": "warning", "message": "Node.js 20 actions are deprecated. Use v5."}
        code, out = self.run_script([[{"id": 1, "name": "lint"}, {"id": 2, "name": "wiring tests"}]], {2: [[note]]})
        self.assertEqual(code, 1)
        self.assertIn("::error::'wiring tests' carries a deprecation warning: Node.js 20 actions are deprecated.", out)

    def test_each_wording_of_the_pattern_is_read(self):
        for message in ("The set-output command is Deprecated", "This runner is no longer supported",
                        "ubuntu-20.04 will be removed on April 1", "ubuntu-20.04 will be disabled", "x will be retired",
                        "Node.js 16 actions are forced to run on node20"):
            with self.subTest(message=message):
                note = {"annotation_level": "failure", "message": message}
                self.assertEqual(self.run_script([[{"id": 1, "name": "a"}]], {1: [[note]]})[0], 1)

    def test_it_reads_every_page_of_jobs_and_of_annotations(self):
        note = {"annotation_level": "failure", "message": "The set-output command is deprecated"}
        code, out = self.run_script([[{"id": 1, "name": "a"}], [{"id": 2, "name": "b"}]], {2: [[], [note]]})
        self.assertEqual(code, 1)
        self.assertIn("'b' carries a deprecation warning", out)

    def test_a_notice_and_other_warnings_do_not_fail(self):
        notes = [[{"annotation_level": "warning", "message": "soft limit reached"},
                  {"annotation_level": "notice", "message": "deprecated but only a notice"}]]
        self.assertEqual(self.run_script([[{"id": 1, "name": "a"}]], {1: notes})[0], 0)

    def test_a_listing_or_a_read_that_fails_is_a_failure_and_not_a_clean_run(self):
        for fail_on, text in (("/jobs", "could not be listed"), ("/annotations", "could not be read")):
            with self.subTest(fail_on=fail_on):
                code, out = self.run_script([[{"id": 1, "name": "a"}]], fail_on=fail_on)
                self.assertEqual(code, 1, out)
                self.assertIn(text, out)
                self.assertNotIn("carries a deprecation warning", out)
                self.assertNotIn("no job of run", out)

    def test_a_run_id_that_is_not_a_number_is_refused_before_anything_is_read(self):
        code, out = self.run_script([[{"id": 1, "name": "a"}]], run_id="9; echo hi")
        self.assertEqual(code, 1)
        self.assertIn("RUN_ID is not a number", out)
        self.assertFalse((self.dir / "calls.log").exists())


class TheWiring(unittest.TestCase):
    def test_the_caller_waits_for_every_suite_runs_always_and_holds_only_read_scopes(self):
        ci = ci_yaml.load(ROOT / ".github/workflows/ci.yml")["jobs"]
        job = ci["deprecations"]
        self.assertEqual(job["uses"], "./.github/workflows/reusable-deprecation-notices.yml")
        self.assertEqual(job["if"], "always()")
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "read", "checks": "read"})
        suites = set(ci) - {"plan", "gate", "deprecations", "dependabot-freshness", "cancel-others", "cancel-first-failure"}
        self.assertEqual(set(job["needs"]), suites)
        self.assertIn("deprecations", ci["gate"]["needs"])

    def test_the_reusable_reads_the_script_of_the_base_and_keeps_its_name_stable(self):
        workflow = ci_yaml.load(REUSABLE)
        self.assertEqual(workflow["permissions"], {})
        job = workflow["jobs"]["notices"]
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "read", "checks": "read"})
        self.assertTrue(job["name"].startswith("no deprecation notices"))
        for event in ("merge_group", "develop", "main", "(promotion)", "format(' ({0})', github.event_name)"):
            self.assertIn(event, job["name"])
        steps = job["steps"]
        checkouts = [s for s in steps if "actions/checkout" in s.get("uses", "")]
        self.assertEqual([c["with"]["path"] for c in checkouts], ["base", "head"])
        self.assertIn("base.sha", checkouts[0]["with"]["ref"])
        self.assertIn("merge_group.base_sha", checkouts[0]["with"]["ref"])
        for c in checkouts:
            self.assertIs(c["with"]["persist-credentials"], False)
        take = next(s for s in steps if s.get("name") == "Take the check from the base commit")["run"]
        self.assertIn('git -C base show "HEAD:$f"', take)
        self.assertIn("|| exit 1", take)  # a base that cannot be read is not a base without the script
        read = next(s for s in steps if s.get("name", "").startswith("Read the annotations"))
        self.assertEqual(read["run"], 'bash "$RUNNER_TEMP/judge/no-deprecation-notices.sh"')
        self.assertNotIn("${{", read["run"])
        self.assertTrue(os.access(SCRIPT, os.X_OK))


if __name__ == "__main__":
    unittest.main()
