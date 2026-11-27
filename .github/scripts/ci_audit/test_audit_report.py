"""The report job of the scheduled audit, run over the artifacts a run can leave behind.

The downloads are modelled on actions/download-artifact: a pattern that matches
one artifact unpacks it straight into `path`, and one that matches several gives
each its own folder named after it. The step that writes the issue runs as
written, with a `gh` that records what it was asked to do.
"""

import fnmatch
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/rust-audit.yml"
CLEAN = {"vulnerabilities": {"found": False, "count": 0, "list": []}}
DIRTY = {"vulnerabilities": {"found": True, "count": 1, "list": [{
    "advisory": {"id": "RUSTSEC-2099-0001"}, "versions": {"patched": [">= 2.0.0"]},
    "package": {"name": "fakecrate", "version": "1.0.0"}}]}}


def report_steps():
    return ci_yaml.load(WORKFLOW)["jobs"]["report"]["steps"]


class Report(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name) / "work"
        (self.work / ".github").mkdir(parents=True)
        (self.work / ".github/scripts").symlink_to(ROOT / ".github/scripts")
        self.log = Path(self.tmp.name) / "gh.log"
        self.bin = Path(self.tmp.name) / "bin"
        self.bin.mkdir()
        gh = self.bin / "gh"
        gh.write_text('#!/bin/sh\nif [ "$2" = list ]; then echo "[]"; exit 0; fi\necho "$*" >> "$GH_LOG"\n')
        gh.chmod(0o755)

    def download(self, artifacts):
        for s in report_steps():
            if not str(s.get("uses", "")).startswith("actions/download-artifact@"):
                continue
            options = s["with"]
            self.assertNotIn("merge-multiple", options)
            names = [n for n in artifacts if fnmatch.fnmatchcase(n, options["pattern"])]
            for name in names:
                target = self.work / options["path"]
                if len(names) > 1:
                    target = target / name
                target.mkdir(parents=True, exist_ok=True)
                (target / "audit.json").write_text(json.dumps(artifacts[name]))

    def report(self, artifacts):
        self.download(artifacts)
        script = next(s for s in report_steps() if "advisory issue" in s.get("name", ""))["run"]
        done = subprocess.run(["bash", "-e", "-c", script], cwd=self.work, capture_output=True, text=True, check=False,
                              env={**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "GH_LOG": str(self.log),
                                   "REPO": "example/repo", "RUN_URL": "https://example.org/run/1"})
        self.assertTrue((self.work / "combined.json").is_file(), done.stderr)
        return done, json.loads((self.work / "combined.json").read_text())

    def test_the_only_artifact_of_a_run_is_still_read(self):
        for ref in ("develop", "main"):
            with self.subTest(ref=ref):
                self.setUp()
                done, combined = self.report({f"audit-json-{ref}": DIRTY})
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(combined["title"], "Dependency advisories: RUSTSEC-2099-0001")
                self.assertIn(f"Dependency advisories open against {ref}.", combined["body"])
                self.assertIn("issue create", self.log.read_text())

    def test_the_branch_that_left_no_artifact_is_named(self):
        done, combined = self.report({"audit-json-main": CLEAN})
        self.assertEqual(combined["title"], "Rust audit failed on develop")
        self.assertEqual(done.returncode, 1, "a failure with no advisory keeps the run red")
        self.assertIn("issue create", self.log.read_text(), "and the issue is written before the job fails")

    def test_two_branches_without_an_artifact_are_both_named(self):
        _, combined = self.report({})
        self.assertEqual(combined["title"], "Rust audit failed on develop, main")

    def test_two_artifacts_are_read_each_under_its_branch(self):
        _, combined = self.report({"audit-json-develop": CLEAN, "audit-json-main": DIRTY})
        self.assertEqual(combined["title"], "Dependency advisories: RUSTSEC-2099-0001")
        self.assertIn("Dependency advisories open against main.", combined["body"])
        self.assertNotIn("open against develop.", combined["body"])

    def test_every_audited_branch_has_a_download_and_a_folder_of_its_own(self):
        refs = ci_yaml.load(WORKFLOW)["jobs"]["audit"]["strategy"]["matrix"]["ref"]
        downloads = {s["with"]["pattern"]: s["with"]["path"] for s in report_steps()
                     if str(s.get("uses", "")).startswith("actions/download-artifact@")}
        self.assertEqual(downloads, {f"audit-json-{ref}": f"audits/audit-json-{ref}" for ref in refs})


if __name__ == "__main__":
    unittest.main()
