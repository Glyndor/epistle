"""Behaviour of is_version_bump.py on throwaway git repositories.

A wrong "yes" lets a code or dependency change skip the workflows that are
not required, so most cases are refusals, and each refusal asserts the reason
as well as the exit status: a script that exits 1 for the wrong reason (a
typo, a missing tool) would otherwise pass every one of them.

Each case writes a realistic Cargo.toml, both lockfiles, debian/changelog and
a docs page, commits them as `base`, applies one change, commits that as
`head` and runs the script on base and head exactly as the workflows do.
"""

import os
import subprocess
import sys
import unittest

from version_bump.fixtures import (
    CHANGELOG,
    GIT_ENV,
    JUDGE,
    NEW,
    OLD,
    SCRIPT,
    Repo,
    bump_all,
    bump_toml,
    new_entry,
    pkg_version,
    read,
    sub,
    write,
)


class VersionBumpTests(unittest.TestCase):
    def judge(self, change, base="base", head="head", **seed_args):
        repo = Repo(change, **seed_args)
        self.addCleanup(repo.close)
        return repo.run(base, head)

    def assert_bump(self, change, **kwargs):
        done = self.judge(change, **kwargs)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(f"a pure version bump: {OLD} -> {NEW}", done.stdout)

    def assert_refused(self, change, reason, **kwargs):
        done = self.judge(change, **kwargs)
        self.assertEqual(done.returncode, 1, done.stdout)
        self.assertIn(reason, done.stderr)

    def test_the_release_bump_passes(self):
        self.assert_bump(bump_all)

    def test_manifest_and_lockfiles_alone_pass(self):
        def change():
            bump_toml()
            pkg_version("Cargo.lock", NEW)
            pkg_version("fuzz/Cargo.lock", NEW)

        self.assert_bump(change)

    def test_a_base_that_moved_on_is_read_from_the_merge_base(self):
        # develop gained a commit after the branch was cut: the pull request
        # still changes only the version, and that is what is judged.
        repo = Repo(bump_all)
        self.addCleanup(repo.close)
        repo.git("checkout", "-q", "-b", "later", "base")
        write(os.path.join(repo.dir, "src/main.rs"), "fn main() { println!(); }\n")
        repo.commit("moved")
        done = repo.run("moved", "head")
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_source_file_is_refused(self):
        def change():
            bump_all()
            write("src/main.rs", "fn main() { loop {} }\n")

        self.assert_refused(change, "src/main.rs is not part of a version bump")

    def test_a_readme_outside_docs_is_refused(self):
        def change():
            bump_all()
            write("README.md", f"epistle {NEW}\n")

        self.assert_refused(change, "README.md is not part of a version bump")

    def test_a_dependency_change_in_the_manifest_is_refused(self):
        def change():
            bump_all()
            sub("Cargo.toml", r'^clap = "4"$', 'clap = "5"')

        self.assert_refused(change, "Cargo.toml changes more than the version")

    def test_a_lockfile_without_the_manifest_is_refused(self):
        def change():
            pkg_version("Cargo.lock", NEW)

        self.assert_refused(change, "Cargo.toml does not change the version")

    def test_another_package_moving_in_the_lockfile_is_refused(self):
        def change():
            bump_all()
            sub("Cargo.lock", r'^version = "4.5.0"$', 'version = "4.6.0"')

        self.assert_refused(change, "Cargo.lock changes more than the version")

    def test_a_checksum_moving_in_the_fuzz_lockfile_is_refused(self):
        def change():
            bump_all()
            write("fuzz/Cargo.lock", read("fuzz/Cargo.lock") + 'checksum = "2"\n')

        self.assert_refused(change, "fuzz/Cargo.lock changes more than the version")

    def test_a_lockfile_on_another_version_is_refused(self):
        def change():
            bump_all()
            pkg_version("fuzz/Cargo.lock", "0.12.7")

        self.assert_refused(change, f"fuzz/Cargo.lock does not move epistle from {OLD} to {NEW}")

    def test_a_second_epistle_package_is_refused(self):
        def change():
            bump_all()
            write("Cargo.lock", read("Cargo.lock") + '\n[[package]]\nname = "epistle"\nversion = "9.9.9"\n')

        self.assert_refused(change, "Cargo.lock in head has no usable version line")

    def test_an_epistle_package_without_a_version_is_refused(self):
        def change():
            bump_all()
            write("Cargo.lock", read("Cargo.lock") + '\n[[package]]\nname = "epistle"\nsource = "x"\n')

        self.assert_refused(change, "Cargo.lock in head has no usable version line")

    def test_a_version_with_a_suffix_is_refused(self):
        def change():
            bump_all()
            sub("Cargo.toml", rf'^version = "{NEW}"$', f'version = "{NEW}-rc1"')

        self.assert_refused(change, "Cargo.toml version in head is not plain X.Y.Z")

    def test_a_suffix_on_the_base_version_is_refused(self):
        def change():
            sub("Cargo.toml", r'^version = ".*"$', f'version = "{NEW}"', count=1)

        self.assert_refused(change, "Cargo.toml version in the base is not plain X.Y.Z", version="0.12.5-rc1")

    def test_a_version_before_the_package_section_is_refused(self):
        def change():
            bump_all()
            write("Cargo.toml", '[dependencies.foo]\nversion = "1.0.0"\n\n' + read("Cargo.toml"))

        self.assert_refused(change, "Cargo.toml in head has no usable version line")

    def test_a_changelog_that_edits_an_earlier_line_is_refused(self):
        def change():
            bump_all()
            sub("debian/changelog", r"^  \* The one before\.$", "  * The one before, reworded.")

        self.assert_refused(change, "edits or removes an earlier line")

    def test_a_changelog_that_shrinks_is_refused(self):
        def change():
            bump_all()
            write("debian/changelog", "\n".join(CHANGELOG.format(v=OLD).split("\n")[6:]))

        self.assert_refused(change, "did not grow")

    def test_a_changelog_entry_for_another_version_is_refused(self):
        def change():
            bump_toml()
            new_entry("0.12.9")

        self.assert_refused(change, f"does not start with the epistle {NEW} entry")

    def test_a_changelog_that_adds_a_partial_line_is_refused(self):
        def change():
            bump_toml()
            write("debian/changelog", f"epistle ({NEW}) unstable;" + read("debian/changelog"))

        self.assert_refused(change, "adds a partial line")

    def test_a_doc_that_changes_more_than_the_version_is_refused(self):
        def change():
            bump_all()
            sub("docs/operations/container.md", r"^Run it:$", "Run it like this:")

        self.assert_refused(change, "docs/operations/container.md changes more than the version")

    def test_a_doc_that_grows_is_refused(self):
        def change():
            bump_all()
            write("docs/operations/container.md", read("docs/operations/container.md") + "More.\n")

        self.assert_refused(change, "adds or removes lines")

    def test_a_new_doc_is_refused(self):
        def change():
            bump_all()
            write("docs/new.md", f"{NEW}\n")

        self.assert_refused(change, "docs/new.md is missing in the base")

    def test_an_empty_range_is_refused(self):
        self.assert_refused(lambda: None, "empty range")

    def test_a_commit_that_does_not_exist_is_refused(self):
        self.assert_refused(bump_all, "failed", head="deadbeef" * 5)

    def test_wrong_arguments_are_refused(self):
        repo = Repo(bump_all)
        self.addCleanup(repo.close)
        done = subprocess.run(
            [sys.executable, "-I", SCRIPT, "base"], cwd=repo.dir, capture_output=True, text=True, check=False
        )
        self.assertEqual(done.returncode, 1)
        self.assertIn("usage", done.stderr)


WORKFLOW = os.path.join(
    os.path.dirname(SCRIPT), "..", "..", "workflows", "reusable-version-bump.yml"
)


def judge_step():
    """The shell of the `judge` step of reusable-version-bump.yml, as written."""
    import yaml

    with open(WORKFLOW, encoding="utf-8") as handle:
        spec = yaml.safe_load(handle)
    steps = spec["jobs"]["judge"]["steps"]
    return next(step["run"] for step in steps if step.get("id") == "judge")


GATE = "${{ !cancelled() && needs.decide.outputs.run != 'false' }}"
REQUIRED_CALLERS = ("ci.yml", "debian.yml", "dco.yml", "line-limit.yml", "supply-chain.yml")


class CallerTests(unittest.TestCase):
    """How the workflows use the answer, read from their files.

    A job gated on `run == 'true'` would skip whenever the judge failed or
    was skipped, which turns every error into a skip; only `!= 'false'`
    keeps the error on the side of running. A required check gated on it
    would report success without running.
    """

    def workflows(self):
        import yaml

        folder = os.path.dirname(WORKFLOW)
        for name in sorted(os.listdir(folder)):
            if name.endswith(".yml") and not name.startswith("reusable-"):
                with open(os.path.join(folder, name), encoding="utf-8") as handle:
                    yield name, yaml.safe_load(handle)

    def test_every_gated_job_runs_unless_the_answer_is_false(self):
        callers = []
        for name, spec in self.workflows():
            jobs = spec.get("jobs", {})
            deciders = {
                job_id
                for job_id, job in jobs.items()
                if job.get("uses") == "./.github/workflows/reusable-version-bump.yml"
            }
            if not deciders:
                continue
            callers.append(name)
            self.assertEqual(deciders, {"decide"}, name)
            for job_id, job in jobs.items():
                if "decide" in str(job.get("needs", "")) or "decide" in str(job.get("if", "")):
                    self.assertEqual(job.get("if"), GATE, f"{name}: {job_id}")
        self.assertEqual(
            callers,
            ["container.yml", "db.yml", "e2e.yml", "imaptest.yml", "interop.yml", "ldap.yml", "upgrade.yml"],
        )

    def test_no_required_check_is_gated(self):
        for name, spec in self.workflows():
            if name in REQUIRED_CALLERS:
                self.assertNotIn("reusable-version-bump.yml", str(spec), name)


class WorkflowStepTests(unittest.TestCase):
    """The workflows run the copy of the judge stored in the base commit.

    These run the step of reusable-version-bump.yml itself, so the test and
    the workflow cannot drift apart.
    """

    def decide(self, change, judge, event="pull_request"):
        repo = Repo(change, judge=judge)
        self.addCleanup(repo.close)
        output = os.path.join(repo.dir, "github-output")
        pull = event == "pull_request"
        done = subprocess.run(
            ["bash", "-e", "-c", judge_step()],
            cwd=repo.dir,
            env={
                **os.environ,
                **GIT_ENV,
                "EVENT_NAME": event,
                "BASE_SHA": "base" if pull else "",
                "HEAD_SHA": "head" if pull else "",
                "RUNNER_TEMP": repo.dir,
                "GITHUB_OUTPUT": output,
            },
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        return read(output)

    def test_a_bump_is_skipped_when_the_base_has_the_judge(self):
        self.assertEqual(self.decide(bump_all, judge=True), "run=false\n")

    def test_a_base_without_the_judge_runs_the_job(self):
        self.assertEqual(self.decide(bump_all, judge=False), "run=true\n")

    def test_a_push_runs_the_job(self):
        self.assertEqual(self.decide(bump_all, judge=True, event="push"), "run=true\n")

    def test_a_head_that_rewrites_the_judge_is_still_judged_by_the_base(self):
        def change():
            bump_all()
            write("src/main.rs", "fn main() { loop {} }\n")
            write(JUDGE, "import sys\nsys.exit(0)\n")

        self.assertEqual(self.decide(change, judge=True), "run=true\n")


if __name__ == "__main__":
    unittest.main()
