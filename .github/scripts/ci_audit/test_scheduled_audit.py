"""The scheduled audit of another branch reads data from it and runs nothing of it."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
REUSABLE = ROOT / ".github/workflows/reusable-rust-audit.yml"


def jobs():
    return ci_yaml.load(REUSABLE)["jobs"]


def step(job, name):
    return next(s for s in jobs()[job]["steps"] if name in s.get("name", ""))


class Shape(unittest.TestCase):
    def test_the_audit_job_has_one_checkout_of_the_event_and_nothing_cached_or_local(self):
        steps = jobs()["audit"]["steps"]
        checkouts = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")]
        self.assertEqual(len(checkouts), 1)
        self.assertEqual(set(checkouts[0]["with"]), {"persist-credentials", "fetch-depth"})
        self.assertIs(checkouts[0]["with"]["persist-credentials"], False)
        for s in steps:
            uses = str(s.get("uses", ""))
            self.assertNotIn("actions/cache", uses)
            self.assertFalse(uses.startswith("./"), "a local action would run code of the tree it sits in")
            self.assertNotIn("ref", s.get("with", {}))

    def test_cargo_deny_runs_only_where_the_tree_is_the_events_own(self):
        self.assertEqual(jobs()["deny"]["if"], "inputs.ref == ''")

    def test_the_branch_is_fetched_by_the_checkout_and_read_with_git_show_only(self):
        take = step("audit", "Take the lockfiles")["run"]
        self.assertIn('git show "origin/${REF}:', take)
        for forbidden in ("git checkout", "git switch", "git worktree", "git clone", "cp ", "cargo "):
            self.assertNotIn(forbidden, take)
        self.assertEqual(step("audit", "Take the lockfiles")["if"], "inputs.ref != ''")


class Behaviour(unittest.TestCase):
    """The two steps, as written, in a repository that has a main and a develop."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.org",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.org"}
        self.env = env

        def git(*args):
            subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=self.repo, env=env, check=True,
                           capture_output=True)
        (self.repo / ".cargo").mkdir()
        (self.repo / "fuzz").mkdir()
        for name, text in (("Cargo.lock", "main\n"), ("fuzz/Cargo.lock", "main fuzz\n"), (".cargo/audit.toml", "main ignores\n")):
            (self.repo / name).write_text(text)
        git("init", "-q", "-b", "main")
        git("add", "-A")
        git("commit", "-qm", "main")
        git("update-ref", "refs/remotes/origin/main", "HEAD")
        git("checkout", "-qb", "develop")
        (self.repo / "Cargo.lock").write_text("develop\n")
        (self.repo / "fuzz/Cargo.lock").write_text("develop fuzz\n")
        (self.repo / ".cargo/audit.toml").unlink()
        git("add", "-A")
        git("commit", "-qm", "develop")
        git("update-ref", "refs/remotes/origin/develop", "HEAD")
        git("checkout", "-q", "main")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        cargo = self.bin / "cargo"
        cargo.write_text("#!/bin/sh\necho \"$* :: $(cat \"$AUDITED_FILE\" 2>/dev/null)\" >> \"$CARGO_LOG\"\n"
                         "echo '{}'\n")
        cargo.chmod(0o755)
        self.temp = self.root / "runner-temp"
        self.temp.mkdir()

    def run_block(self, text, **env):
        return subprocess.run(["bash", "-e", "-c", text], cwd=self.repo, capture_output=True, text=True, check=False,
                              env={**self.env, "PATH": f"{self.bin}:{os.environ['PATH']}", "RUNNER_TEMP": str(self.temp),
                                   "GITHUB_OUTPUT": str(self.root / "out"), "CARGO_LOG": str(self.root / "cargo.log"), **env})

    def audit(self, ref):
        env = {"REF": ref, "WORKDIR": ".", "EXTRA_LOCKFILES": "fuzz/Cargo.lock"}
        done = self.run_block(step("audit", "Take the lockfiles")["run"], **env)
        self.assertEqual(done.returncode, 0, done.stderr)
        out = (self.root / "out").read_text()
        audited = out.split("dir=")[1].strip()
        return audited, env

    def test_the_audited_branchs_lockfiles_land_outside_the_workspace_and_are_the_ones_audited(self):
        audited, _ = self.audit("develop")
        self.assertFalse(audited.startswith(str(self.repo)))
        self.assertEqual((Path(audited) / "Cargo.lock").read_text(), "develop\n")
        self.assertEqual((Path(audited) / "fuzz/Cargo.lock").read_text(), "develop fuzz\n")
        self.assertFalse((Path(audited) / ".cargo/audit.toml").exists(), "develop has no ignore list")
        self.assertEqual((self.repo / "Cargo.lock").read_text(), "main\n", "the workspace is not touched")
        (self.repo / "audit.log").write_text("")
        done = self.run_block(step("audit", "Run cargo audit")["run"], AUDITED_DIR=audited)
        self.assertEqual(done.returncode, 0, done.stderr)
        calls = (self.root / "cargo.log").read_text()
        self.assertIn(f"--file {audited}/Cargo.lock", calls)
        self.assertNotIn("--config", calls)

    def test_the_ignore_list_of_the_audited_branch_is_passed_when_it_has_one(self):
        audited, _ = self.audit("main")
        self.assertEqual((Path(audited) / ".cargo/audit.toml").read_text(), "main ignores\n")
        done = self.run_block(step("audit", "Run cargo audit")["run"], AUDITED_DIR=audited)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(f"--config {audited}/.cargo/audit.toml", (self.root / "cargo.log").read_text())

    def test_extra_lockfiles_are_audited_from_the_taken_copy(self):
        audited, env = self.audit("develop")
        done = self.run_block(step("audit", "extra lockfiles")["run"], AUDITED_DIR=audited, EXTRA_LOCKFILES=env["EXTRA_LOCKFILES"])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(f"--file {audited}/fuzz/Cargo.lock", (self.root / "cargo.log").read_text())

    def test_a_pull_request_audits_its_own_tree_with_no_taken_copy(self):
        done = self.run_block(step("audit", "Run cargo audit")["run"], AUDITED_DIR="")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn("--file", (self.root / "cargo.log").read_text())

    def test_a_branch_that_lacks_a_lockfile_fails_the_step(self):
        done = self.run_block(step("audit", "Take the lockfiles")["run"], REF="nope", WORKDIR=".", EXTRA_LOCKFILES="")
        self.assertNotEqual(done.returncode, 0)


if __name__ == "__main__":
    unittest.main()
