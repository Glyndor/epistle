"""The scheduled audit of another branch reads data from it and runs nothing of it."""

import os
import re
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


def fetch_depth(ref):
    """The depth the checkout of the audit job asks for when the `ref` input is `ref`.

    Actions and Python agree on what `&&` and `||` return and on 0 and '' being
    false, so the expression is evaluated here once its few tokens are translated.
    """
    checkout = next(s for s in jobs()["audit"]["steps"] if str(s.get("uses", "")).startswith("actions/checkout@"))
    expression = re.fullmatch(r"\$\{\{(.*)\}\}", str(checkout["with"]["fetch-depth"])).group(1)
    token = r"\s+|inputs\.ref|==|!=|&&|\|\||''|'[a-z]+'|[0-9]+"
    if not re.fullmatch(f"(?:{token})+", expression):
        raise AssertionError(f"this test cannot evaluate {expression!r}")
    python = expression.replace("inputs.ref", repr(ref)).replace("&&", " and ").replace("||", " or ")
    return int(eval(python.strip(), {"__builtins__": {}}))


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


class Triggers(unittest.TestCase):
    def test_the_audit_runs_on_schedule_and_dispatch_only_and_audits_both_branches(self):
        workflow = ci_yaml.load(ROOT / ".github/workflows/rust-audit.yml")
        self.assertEqual(set(workflow[True]), {"schedule", "workflow_dispatch"})
        self.assertEqual(workflow["jobs"]["audit"]["strategy"]["matrix"]["ref"], ["develop", "main"])
        # The pull request and the queue entry are audited by the gate in ci.yml, on every change; a push
        # to develop would audit the commit the queue just audited.
        self.assertNotIn("paths", str(workflow[True]))

    def test_a_push_never_opens_or_closes_an_issue(self):
        jobs = ci_yaml.load(ROOT / ".github/workflows/rust-audit.yml")["jobs"]
        for name in ("report", "close"):
            self.assertIn("github.event_name != 'push'", jobs[name]["if"], name)
            self.assertIn("github.event_name != 'pull_request'", jobs[name]["if"], name)


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
        cargo.write_text("#!/bin/sh\necho \"cwd=$PWD $*\" >> \"$CARGO_LOG\"\n"
                         "echo '{}'\n")
        cargo.chmod(0o755)
        self.temp = self.root / "runner-temp"
        self.temp.mkdir()

    def checkout(self, depth):
        """What actions/checkout leaves on a scheduled run, whose event is `main`.

        A depth above 0 fetches the commit of the event and nothing else; 0 fetches
        every branch into `refs/remotes/origin/`.
        """
        work = Path(tempfile.mkdtemp(prefix="checkout-", dir=self.root))

        def git(*args):
            return subprocess.run(["git", *args], cwd=work, env=self.env, check=True, capture_output=True, text=True)
        git("init", "-q")
        git("remote", "add", "origin", self.repo.as_uri())
        if depth > 0:
            sha = subprocess.run(["git", "rev-parse", "main"], cwd=self.repo, check=True, capture_output=True,
                                 text=True).stdout.strip()
            git("fetch", "-q", "--no-tags", f"--depth={depth}", "origin", f"+{sha}:refs/remotes/origin/main")
        else:
            git("fetch", "-q", "origin", "+refs/heads/*:refs/remotes/origin/*")
        git("checkout", "-q", "-B", "main", "refs/remotes/origin/main")
        return work

    def run_block(self, text, cwd=None, **env):
        return subprocess.run(["bash", "-e", "-c", text], cwd=cwd or self.repo, capture_output=True, text=True,
                              check=False,
                              env={**self.env, "PATH": f"{self.bin}:{os.environ['PATH']}", "RUNNER_TEMP": str(self.temp),
                                   "GITHUB_OUTPUT": str(self.root / "out"), "CARGO_LOG": str(self.root / "cargo.log"), **env})

    def audit(self, ref):
        env = {"REF": ref, "WORKDIR": ".", "EXTRA_LOCKFILES": "fuzz/Cargo.lock"}
        done = self.run_block(step("audit", "Take the lockfiles")["run"], **env)
        self.assertEqual(done.returncode, 0, done.stderr)
        out = (self.root / "out").read_text()
        audited = out.split("dir=")[1].strip()
        return audited, env

    def test_the_checkout_brings_the_branch_the_next_step_reads(self):
        for ref in ("develop", "main"):
            with self.subTest(ref=ref):
                work = self.checkout(fetch_depth(ref))
                done = self.run_block(step("audit", "Take the lockfiles")["run"], cwd=work, REF=ref, WORKDIR=".",
                                      EXTRA_LOCKFILES="fuzz/Cargo.lock")
                self.assertEqual(done.returncode, 0, done.stderr)
                audited = (self.root / "out").read_text().split("dir=")[-1].strip()
                self.assertEqual((Path(audited) / "Cargo.lock").read_text(), f"{ref}\n")

    def test_a_run_that_audits_its_own_tree_fetches_one_commit(self):
        self.assertEqual(fetch_depth(""), 1)

    def test_the_audited_branchs_lockfiles_land_outside_the_workspace_and_are_the_ones_audited(self):
        audited, _ = self.audit("develop")
        self.assertFalse(audited.startswith(str(self.repo)))
        self.assertEqual((Path(audited) / "Cargo.lock").read_text(), "develop\n")
        self.assertEqual((Path(audited) / "fuzz/Cargo.lock").read_text(), "develop fuzz\n")
        self.assertEqual((Path(audited) / ".cargo/audit.toml").read_text(), "[advisories]\nignore = []\n",
                         "develop has no ignore list, so it gets an empty one and no other can apply")
        self.assertEqual((self.repo / "Cargo.lock").read_text(), "main\n", "the workspace is not touched")
        (self.repo / "audit.log").write_text("")
        done = self.run_block(step("audit", "Run cargo audit")["run"], AUDITED_DIR=audited)
        self.assertEqual(done.returncode, 0, done.stderr)
        calls = (self.root / "cargo.log").read_text()
        self.assertIn(f"--file {audited}/Cargo.lock", calls)
        self.assertIn(f"cwd={audited} ", calls, "the audit runs inside the clean directory")
        self.assertNotIn("--config", calls)

    def test_the_ignore_list_of_the_audited_branch_is_found_by_the_working_directory_when_it_has_one(self):
        audited, _ = self.audit("main")
        self.assertEqual((Path(audited) / ".cargo/audit.toml").read_text(), "main ignores\n")
        done = self.run_block(step("audit", "Run cargo audit")["run"], AUDITED_DIR=audited)
        self.assertEqual(done.returncode, 0, done.stderr)
        calls = (self.root / "cargo.log").read_text()
        self.assertIn(f"cwd={audited} ", calls)
        self.assertNotIn("--config", calls, "the flag is not trusted: the working directory decides")
        self.assertEqual((self.repo / "audit.json").read_text().strip(), "{}")

    def test_extra_lockfiles_are_audited_from_the_taken_copy(self):
        audited, env = self.audit("develop")
        done = self.run_block(step("audit", "extra lockfiles")["run"], AUDITED_DIR=audited, EXTRA_LOCKFILES=env["EXTRA_LOCKFILES"])
        self.assertEqual(done.returncode, 0, done.stderr)
        calls = (self.root / "cargo.log").read_text()
        self.assertIn(f"--file {audited}/fuzz/Cargo.lock", calls)
        self.assertIn(f"cwd={audited} ", calls)

    def test_a_pull_request_audits_its_own_tree_with_no_taken_copy(self):
        done = self.run_block(step("audit", "Run cargo audit")["run"], AUDITED_DIR="")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn("--file", (self.root / "cargo.log").read_text())

    def test_a_branch_that_lacks_a_lockfile_fails_the_step(self):
        done = self.run_block(step("audit", "Take the lockfiles")["run"], REF="nope", WORKDIR=".", EXTRA_LOCKFILES="")
        self.assertNotEqual(done.returncode, 0)


if __name__ == "__main__":
    unittest.main()
