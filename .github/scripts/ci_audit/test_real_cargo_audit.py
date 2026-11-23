"""The scheduled audit against the real cargo-audit, with an advisory database made for the test.

A fake cargo proves the arguments; only the real tool proves which list of
ignores it reads. These tests need `cargo-audit` on the PATH and skip with that
reason when it is missing (the CI job that runs the scripts does not carry it).
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / ".github/scripts"
REUSABLE = ROOT / ".github/workflows/reusable-rust-audit.yml"
ADVISORY = """```toml
[advisory]
id = "RUSTSEC-2099-0001"
package = "fakecrate"
date = "2099-01-01"
url = "https://example.org/1"
categories = ["denial-of-service"]
[versions]
patched = [">= 2.0.0"]
```

# fakecrate is broken

Fixture.
"""
LOCK = """version = 3

[[package]]
name = "fakecrate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"

[[package]]
name = "demo"
version = "0.1.0"
dependencies = ["fakecrate"]
"""
IGNORE_IT = '[advisories]\nignore = ["RUSTSEC-2099-0001"]\n'


def step(name):
    steps = ci_yaml.load(REUSABLE)["jobs"]["audit"]["steps"]
    return next(s for s in steps if name in s.get("name", ""))["run"]


@unittest.skipUnless(shutil.which("cargo-audit"), "cargo-audit is not installed here")
class RealTool(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.root = Path(self.tmp.name)
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}
        self.env = env

        def git(cwd, *args):
            subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=cwd, env=env, check=True, capture_output=True)

        db = root / "db"
        (db / "crates/fakecrate").mkdir(parents=True)
        (db / "crates/fakecrate/RUSTSEC-2099-0001.md").write_text(ADVISORY)
        git(db, "init", "-q")
        git(db, "add", "-A")
        git(db, "commit", "-qm", "db")
        # The workspace is main's checkout and carries a list that ignores the advisory.
        self.ws = root / "ws"
        (self.ws / ".cargo").mkdir(parents=True)
        (self.ws / "Cargo.lock").write_text(LOCK)
        (self.ws / ".cargo/audit.toml").write_text(IGNORE_IT)
        git(self.ws, "init", "-q", "-b", "main")
        git(self.ws, "add", "-A")
        git(self.ws, "commit", "-qm", "main")
        git(self.ws, "update-ref", "refs/remotes/origin/main", "HEAD")
        # develop has the vulnerable lockfile and, depending on the test, a list or none.
        git(self.ws, "checkout", "-qb", "develop")
        (self.ws / ".cargo/audit.toml").unlink()
        git(self.ws, "add", "-A")
        git(self.ws, "commit", "-qm", "develop without a list")
        git(self.ws, "update-ref", "refs/remotes/origin/develop", "HEAD")
        git(self.ws, "checkout", "-qb", "develop-with-list", "main")
        git(self.ws, "update-ref", "refs/remotes/origin/develop-with-list", "HEAD")
        git(self.ws, "checkout", "-q", "main")
        # `cargo audit ...` runs the real cargo-audit against the fixture database.
        self.bin = root / "bin"
        self.bin.mkdir()
        shim = self.bin / "cargo"
        shim.write_text('#!/bin/sh\n[ "$1" = audit ] || exit 2\nshift\n'
                        f'exec cargo-audit audit --db {db} --no-fetch --no-yanked "$@"\n')
        shim.chmod(0o755)
        self.temp = root / "runner-temp"
        self.temp.mkdir()

    def run_block(self, text, **env):
        return subprocess.run(["bash", "-e", "-c", text], cwd=self.ws, capture_output=True, text=True, check=False,
                              env={**self.env, "PATH": f"{self.bin}:{os.environ['PATH']}", "RUNNER_TEMP": str(self.temp),
                                   "GITHUB_OUTPUT": str(self.root / "out"), **env})

    def take(self, ref):
        done = self.run_block(step("Take the lockfiles"), REF=ref, WORKDIR=".", EXTRA_LOCKFILES="")
        self.assertEqual(done.returncode, 0, done.stderr)
        return (self.root / "out").read_text().split("dir=")[1].split()[0]

    def audit(self, audited):
        return self.run_block(step("Run cargo audit"), AUDITED_DIR=audited)

    def test_an_advisory_the_audited_branch_ignores_does_not_fail(self):
        audited = self.take("develop-with-list")
        self.assertEqual((Path(audited) / ".cargo/audit.toml").read_text(), IGNORE_IT)
        done = self.audit(audited)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_an_advisory_it_does_not_ignore_fails_even_if_the_workspace_ignores_it(self):
        self.assertTrue((self.ws / ".cargo/audit.toml").exists(), "the workspace carries a list that would hide it")
        subprocess.run(["git", "checkout", "-q", "main"], cwd=self.ws, check=True)
        audited = self.take("develop")
        self.assertEqual((Path(audited) / ".cargo/audit.toml").read_text(), "[advisories]\nignore = []\n")
        done = self.audit(audited)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)

    def test_the_report_is_written_to_the_workspace_by_absolute_path_and_names_the_advisory(self):
        audited = self.take("develop")
        self.audit(audited)
        report = json.loads((self.ws / "audit.json").read_text())
        self.assertTrue(report["vulnerabilities"]["found"])
        self.assertEqual(report["vulnerabilities"]["list"][0]["advisory"]["id"], "RUSTSEC-2099-0001")
        self.assertFalse((Path(audited) / "audit.json").exists())

    def test_a_pull_request_audits_its_own_tree_with_its_own_list(self):
        done = self.audit("")
        self.assertEqual(done.returncode, 0, done.stderr)  # main's checkout ignores the advisory

    def test_the_extra_lockfile_step_uses_the_same_working_directory(self):
        (self.ws / "fuzz").mkdir(exist_ok=True)
        subprocess.run(["git", "checkout", "-q", "develop"], cwd=self.ws, check=True)
        (self.ws / "fuzz/Cargo.lock").write_text(LOCK)
        subprocess.run(["git", "add", "-A"], cwd=self.ws, check=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qm", "fuzz"], cwd=self.ws, env=self.env, check=True, capture_output=True)
        subprocess.run(["git", "update-ref", "refs/remotes/origin/develop", "HEAD"], cwd=self.ws, check=True)
        subprocess.run(["git", "checkout", "-q", "main"], cwd=self.ws, check=True)
        done = self.run_block(step("Take the lockfiles"), REF="develop", WORKDIR=".", EXTRA_LOCKFILES="fuzz/Cargo.lock")
        self.assertEqual(done.returncode, 0, done.stderr)
        audited = (self.root / "out").read_text().split("dir=")[1].split()[0]
        done = self.run_block(step("extra lockfiles"), AUDITED_DIR=audited, EXTRA_LOCKFILES="fuzz/Cargo.lock")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertTrue((self.ws / "audit-fuzz-Cargo.json").exists())


class CombineFailsClosed(unittest.TestCase):
    """The script that turns the reports into an issue never reads a broken report as a clean one."""

    def run_combine(self, develop, *extra):
        with tempfile.TemporaryDirectory() as tmp:
            for ref, text in (("develop", develop), ("main", '{"vulnerabilities":{"found":false,"count":0,"list":[]}}')):
                folder = Path(tmp) / f"audit-json-{ref}"
                folder.mkdir()
                if text is not None:
                    (folder / "audit.json").write_text(text)
            return subprocess.run(["python3", "-I", str(SCRIPTS / "rust_audit_combine.py"), tmp, "--no-lookup", *extra],
                                  capture_output=True, text=True, check=False)

    def test_empty_invalid_or_incomplete_json_is_exit_2_and_never_clean(self):
        for text in ("", "not json", "{}", "[]", "null", '{"vulnerabilities": 3}'):
            with self.subTest(text=text):
                done = self.run_combine(text)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertNotIn('"clean": true', done.stdout)

    def test_a_ref_that_produced_no_report_still_opens_the_failure_issue(self):
        # The workflow always passes --run-url, and a combine with nothing to report
        # then becomes an issue about the run, never silence.
        done = self.run_combine(None, "--run-url", "https://example.org/run/1")
        self.assertEqual(done.returncode, 0, done.stderr)
        result = json.loads(done.stdout)
        self.assertTrue(result["title"].startswith("Rust audit failed on"))
        self.assertIn("https://example.org/run/1", result["body"])

    def test_a_report_that_is_complete_and_clean_is_clean(self):
        done = self.run_combine('{"vulnerabilities":{"found":false,"count":0,"list":[]}}')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn('"clean": true', done.stdout)


if __name__ == "__main__":
    unittest.main()
