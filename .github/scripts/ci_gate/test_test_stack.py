"""The jobs that run the unit tests give a test thread the stack the command line needs."""

import subprocess
import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
STACK = "8388608"


class TestThreadStack(unittest.TestCase):
    def test_the_workflows_that_run_the_library_tests_set_it_for_every_job(self):
        for name in ("reusable-rust-ci.yml", "db.yml"):
            workflow = ci_yaml.load(ROOT / ".github/workflows" / name)
            self.assertEqual(workflow["env"], {"RUST_MIN_STACK": STACK}, name)
            for job_id, job in workflow["jobs"].items():
                self.assertNotIn("RUST_MIN_STACK", str(job.get("env", {})), f"{name}:{job_id} overrides it")

    def test_the_command_a_contributor_runs_carries_the_same_value(self):
        self.assertIn(f"RUST_MIN_STACK={STACK} cargo test --locked --all-features --workspace", (ROOT / "CONTRIBUTING.md").read_text())

    def test_no_cargo_config_is_tracked_because_the_debian_build_reads_its_presence(self):
        tracked = subprocess.check_output(["git", "ls-files", ".cargo"], cwd=ROOT, text=True).split()
        self.assertNotIn(".cargo/config.toml", tracked)
        rules = (ROOT / "debian/rules").read_text()
        self.assertIn("$(wildcard .cargo/config.toml)", rules)


if __name__ == "__main__":
    unittest.main()
