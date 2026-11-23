"""The tools the workflows install: one version where two files must agree, and a digest next to every download."""

import re
import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github/workflows"


class Agreement(unittest.TestCase):
    def test_the_two_coverage_jobs_use_one_version_of_the_tool(self):
        reusable = ci_yaml.load(WORKFLOWS / "reusable-rust-ci.yml")[True]["workflow_call"]["inputs"]["llvm-cov-version"]["default"]
        db = ci_yaml.load(WORKFLOWS / "db.yml")
        versions = {
            step["env"]["LLVM_COV_VERSION"]
            for job in db["jobs"].values()
            for step in job.get("steps", [])
            if "LLVM_COV_VERSION" in step.get("env", {})
        }
        self.assertEqual(versions, {reusable})

    def test_the_toolchain_of_the_audit_is_the_one_ci_builds_with(self):
        audit = ci_yaml.load(WORKFLOWS / "reusable-rust-audit.yml")[True]["workflow_call"]["inputs"]["toolchain"]["default"]
        ci = ci_yaml.load(WORKFLOWS / "ci.yml")["jobs"]["rust"]["with"]["toolchain"]
        self.assertEqual(audit, ci)


class Digests(unittest.TestCase):
    def test_the_editorconfig_checker_is_pinned_by_version_and_digest_and_checked_before_it_runs(self):
        step = ci_yaml.load(WORKFLOWS / "editorconfig.yml")["jobs"]["editorconfig"]["steps"][1]
        self.assertRegex(step["env"]["ECLINT_VERSION"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(step["env"]["ECLINT_SHA256"], r"^[0-9a-f]{64}$")
        run = step["run"]
        self.assertLess(run.index("sha256sum --check --strict"), run.index("tar -xzf"))
        self.assertIn("--proto '=https'", run)
        self.assertLess(run.index("tar -xzf"), run.index('"$tool/editorconfig-checker" --disable-indentation'))

    def test_no_workflow_downloads_a_program_and_runs_it_without_a_digest(self):
        for path in ci_yaml.workflow_files(ROOT):
            text = path.read_text()
            code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
            if re.search(r"curl[^\n]*(github\.com|githubusercontent)[^\n]*", code) or "curl" in code and "releases/download" in code:
                self.assertIn("sha256sum --check", code, path.name)


if __name__ == "__main__":
    unittest.main()
