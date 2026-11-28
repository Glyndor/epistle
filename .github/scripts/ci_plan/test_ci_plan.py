"""Selection policy, real Git ranges, and the workflow steps that consume it."""

import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import ci_yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location("planner", HERE / "ci_plan.py")
cp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cp)
SCRIPT = ".github/scripts/ci_plan/ci_plan.py"


def workflow(name):
    return ci_yaml.load(ROOT / ".github/workflows" / name)


class SelectionTests(unittest.TestCase):
    def selected(self, *paths, status="M", event="pull_request", always=False):
        """The jobs a change selects. The two that judge the whole tree always run, so they are left out."""
        chosen = {job for job, run in cp.select(event, [(status, p) for p in paths]).items() if run}
        return chosen if always or event != "pull_request" else chosen - cp.ALWAYS

    def test_the_line_and_folder_gates_judge_the_tree_and_always_run(self):
        for path in ("README.md", "docs/a.md", "src/lib.rs", "Cargo.lock", ".gitignore"):
            self.assertTrue(cp.ALWAYS <= self.selected(path, always=True), path)

    def test_docs_edits_skip_unaffected_work(self):
        self.assertEqual(self.selected("README.md"), set())
        self.assertEqual(self.selected("docs/operations/queue.md"), {"tests"})

    def test_new_docs_need_the_suite_only(self):
        self.assertEqual(self.selected("docs/new.md", status="A"), {"tests"})

    def test_test_only_changes_keep_suite_and_lint(self):
        for path in ("tests/smtp/hostile.rs", "src/cli/tests/base.rs",
                     "src/imap/session_tests.rs", "src/dns/tests_wire.rs",
                     "src/imap/parse_tests_extra.rs", "src/test_support.rs"):
            with self.subTest(path=path):
                self.assertEqual(self.selected(path), {"lint", "tests"})

    def test_test_fixtures_still_run_tests(self):
        self.assertEqual(self.selected("tests/fixtures/signed.eml"), {"lint", "tests"})

    def test_test_names_do_not_match_production_substrings(self):
        for path in ("src/contest.rs", "src/tests_util/mod.rs", "src/dns/testing.rs"):
            self.assertTrue(cp.BUILD <= self.selected(path))

    def test_source_and_build_inputs_run_build_checks(self):
        for path in ("src/smtp/mod.rs", "src/api/openapi/openapi.yaml",
                     "migrations/001.sql", ".sqlx/query.json", "build.rs"):
            with self.subTest(path=path):
                self.assertTrue(cp.BUILD <= self.selected(path))

    def test_manifests_and_locks_also_run_supply_and_freshness(self):
        for path in ("Cargo.toml", "Cargo.lock", ".cargo/config.toml"):
            self.assertTrue(cp.BUILD | {"supply", "freshness"} <= self.selected(path))

    def test_supply_inputs_do_not_compile_the_workspace(self):
        for path in ("about.hbs", "about.toml", "deny.toml", "LICENSE"):
            self.assertEqual(self.selected(path), {"supply"})

    def test_debian_changes_keep_packaging_and_contract_tests(self):
        self.assertEqual(self.selected("debian/rules"), {"debian", "packages", "tests"})

    def test_a_change_to_the_packaging_of_the_other_distributions_runs_the_deb_and_its_checks_and_nothing_else(self):
        for path in (".github/scripts/distro_packages/stage_payload.py", ".github/scripts/distro_packages/rpm/epistle.spec.in",
                     ".github/scripts/distro_packages/images.env", "packaging/linux/setup.sh",
                     "tests/packaging/rpm/verify-rpm.sh", "tests/packaging/payload/verify-matches-deb.sh",
                     "tests/packaging/host/lifecycle.sh", "tests/packaging/pacman/admission.sh",
                     ".github/scripts/distro_packages/pacman/PKGBUILD"):
            with self.subTest(path=path):
                self.assertEqual(self.selected(path), {"debian", "packages"})

    def test_what_the_admission_check_installs_its_tools_with_runs_it_and_still_runs_the_tests(self):
        for path in cp.SIGNING:
            self.assertTrue((ROOT / path).is_file(), path)
            self.assertEqual(self.selected(path), {"debian", "packages", "tests"}, path)

    def test_the_package_checks_never_run_without_the_deb_they_are_packed_from(self):
        listing = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).split("\n")
        for path in [p for p in listing if p] + ["a-new-file", ".github/workflows/new.yml"]:
            chosen = self.selected(path)
            if "packages" in chosen:
                self.assertIn("debian", chosen, path)

    def test_changes_that_cannot_reach_a_package_skip_the_package_checks(self):
        for path in ("README.md", "docs/a.md", "src/smtp/mod.rs", "Cargo.lock", "tests/smtp/hostile.rs",
                     "tests/packaging/debian/sysctl.rs", ".github/scripts/release/release_files.py", "deny.toml"):
            self.assertNotIn("packages", self.selected(path), path)

    def test_every_check_under_the_packaging_tests_is_run_by_something_the_plan_selects(self):
        """A shell check nobody calls is a check that does not exist: each one is named by the CI job or by a script it runs."""
        callers = [ROOT / ".github/workflows/ci.yml", *sorted((ROOT / ".github/scripts/distro_packages").glob("*.sh"))]
        checks = sorted((ROOT / "tests/packaging").rglob("*.sh"))
        self.assertGreater(len(checks), 4)
        reached = "".join(path.read_text() for path in callers)
        for check in checks:
            reached_by = reached + "".join(other.read_text() for other in checks if other != check)
            self.assertIn(check.name, reached_by, check.name)
            self.assertIn("packages", self.selected(check.relative_to(ROOT).as_posix()), check.name)

    def test_folder_gate_runs_whatever_the_change_is(self):
        for status in ("A", "D", "M"):
            for path in ("src/imap/x.rs", "README.md", ".github/folder-limit-exceptions.txt", "scripts/folder-limit/folder-limit.sh"):
                self.assertTrue(cp.select("pull_request", [(status, path)])["folder"], (status, path))

    def test_mixed_change_takes_union(self):
        self.assertEqual(self.selected("README.md", "tests/x.rs", "about.hbs"),
                         {"lint", "tests", "supply"})

    def test_classifier_and_unknown_paths_run_everything(self):
        for path in (*cp.OWN, "a-new-build-input", ".github/workflows/new-build.yml"):
            self.assertEqual(self.selected(path, always=True), set(cp.JOBS))

    # The files that select no suite at all, exactly. Moving a file here, or one out,
    # is a decision this list records: each of these either has a workflow of its
    # own that runs by its path filter or is read by no suite.
    NOTHING = {
        ".containerignore",  # read by container.yml, which runs on its own paths
        ".editorconfig",  # read by editorconfig.yml
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".gitignore",
        "CONTRIBUTING.md",
        "Containerfile",  # built by container.yml
        "README.md",
        # Judged by the folder gate, which runs on every pull request.
        ".github/folder-limit-exceptions.txt",
        "scripts/folder-limit/folder-limit.sh",
        "scripts/folder-limit/folder-limit.test.sh",
    }

    def test_every_workflow_and_action_selects_the_suites_it_runs_and_the_tests_that_read_it(self):
        """The machinery of the map: a change to a file a suite uses selects that suite, whatever the suffix."""
        files = [p.relative_to(ROOT).as_posix() for p in (*ci_yaml.workflow_files(ROOT), *ci_yaml.action_files(ROOT))]
        self.assertGreater(len(files), 25)
        for path in files:
            chosen = self.selected(path)
            self.assertIn("tests", chosen, path)
            owned = cp.WORKFLOWS.get(path.rsplit("/", 1)[-1], set())
            self.assertTrue(owned - cp.ALWAYS <= chosen, path)
        # Nothing in there selects less than the tests, and a new file with either suffix is treated the same.
        for path in (".github/workflows/new-suite.yml", ".github/workflows/new-suite.yaml",
                     ".github/actions/new/action.yaml", ".github/actions/new/action.yml"):
            self.assertIn("tests", self.selected(path), path)
        self.assertEqual(self.selected(".github/workflows/ci-e2e.yaml"), set(cp.JOBS) - cp.ALWAYS)

    def test_the_files_that_select_no_suite_are_exactly_the_listed_ones(self):
        listing = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).split("\n")
        nothing = {path for path in listing if path and not self.selected(path)}
        self.assertEqual(nothing, self.NOTHING)

    def test_the_files_that_change_what_is_built_select_exactly_their_suites(self):
        everything_rust = cp.RUST | {"debian"}
        table = {
            "Cargo.toml": everything_rust | {"supply", "freshness"},
            "Cargo.lock": everything_rust | {"supply", "freshness"},
            ".cargo/config.toml": everything_rust | {"supply", "freshness"},
            "rust-toolchain.toml": everything_rust | {"supply"},
            "build.rs": everything_rust | {"supply"},
            ".sqlx/query-1.json": everything_rust,
            "migrations/0001_init.sql": everything_rust,
            "src/main.rs": everything_rust,
            "deny.toml": {"supply"},
            "about.toml": {"supply"},
            "about.hbs": {"supply"},
            "LICENSE": {"supply"},
            "rustfmt.toml": {"lint"},
            "debian/rules": {"debian", "packages", "tests"},
            "debian/control": {"debian", "packages", "tests"},
            "packaging/linux/sysusers.conf": {"debian", "packages"},
            "deploy/images/Dockerfile": {"tests"},
            "scripts/ci/x.sh": {"tests"},
            "install.sh": set(cp.JOBS) - cp.ALWAYS,
            "fuzz/Cargo.lock": {"lint"},
            ".github/codeql/codeql-config.yml": {"lint", "tests"},
            ".github/scripts/ci_codeql/check_paths.py": {"lint", "tests"},
            ".github/scripts/ci_codeql/dep_info.py": {"lint", "tests"},
            ".github/dependabot.yml": {"freshness"},
            ".github/workflows/ci.yml": everything_rust | {"freshness", "packages", "supply"},
            ".github/workflows/reusable-rust-ci.yml": cp.RUST,
            ".github/workflows/reusable-rust-debian.yml": {"debian", "packages", "tests"},
            ".github/workflows/reusable-rust-supply-chain.yml": {"supply", "tests"},
            ".github/workflows/reusable-line-limit.yml": {"tests"},
            ".github/workflows/reusable-dependabot-freshness.yml": {"freshness", "tests"},
        }
        for path, expected in table.items():
            with self.subTest(path=path):
                self.assertEqual(self.selected(path), expected - cp.ALWAYS)

    def test_non_pr_events_and_empty_diff_run_everything(self):
        for event in ("merge_group", "push", "schedule", "workflow_dispatch", ""):
            self.assertEqual(self.selected("README.md", event=event, always=True), set(cp.JOBS))
        self.assertEqual(self.selected(always=True), set(cp.JOBS))

    def test_workflows_and_dependency_config_select_their_consumers(self):
        for filename, jobs in cp.WORKFLOWS.items():
            self.assertTrue(jobs | {"tests"} <= self.selected(f".github/workflows/{filename}", always=True), filename)
        self.assertEqual(self.selected(".github/dependabot.yml"), {"freshness"})


class GitPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.env = {**os.environ, "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.org",
                    "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.org"}
        self.git("init", "-q")
        self.write(SCRIPT, (HERE / "ci_plan.py").read_text())
        self.write("README.md", "base docs\n")
        self.write("src/service.rs", "fn service() {}\n")
        self.base = self.commit()
        self.head = self.base

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "commit.gpgsign=false", *args],
                                       cwd=self.repo, env=self.env, text=True).strip()

    def write(self, path, content):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qsm", "test: prepare fixture")
        return self.git("rev-parse", "HEAD")

    @staticmethod
    def chosen(plan):
        return {job for job, run in plan.items() if run == "true"}

    def plan(self, event="pull_request", base=None, head=None, base_ref="develop"):
        output = self.repo / "outputs"
        output.write_text("")
        step = workflow("reusable-ci-plan.yml")["jobs"]["plan"]["steps"][-1]["run"]
        done = subprocess.run(["bash", "-c", step], cwd=self.repo,
                              env={**self.env, "EVENT_NAME": event, "BASE_SHA": base or self.base,
                                   "HEAD_SHA": head or self.head, "BASE_REF": base_ref, "GITHUB_OUTPUT": str(output),
                                   "RUNNER_TEMP": str(self.repo)}, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return dict(line.split("=", 1) for line in output.read_text().splitlines())

    def test_docs_diff_through_actual_workflow_step(self):
        self.write("README.md", "updated docs\n")
        self.head = self.commit()
        self.assertEqual(self.chosen(self.plan()), cp.ALWAYS)

    def test_rename_keeps_old_production_path_and_new_doc_path(self):
        self.git("mv", "src/service.rs", "service.md")
        self.head = self.commit()
        result = self.plan()
        for job in cp.BUILD | {"lines", "folder"}:
            self.assertEqual(result[job], "true")

    def test_delete_test_keeps_suite_but_skips_builds(self):
        self.write("tests/old.rs", "#[test] fn old() {}\n")
        self.base = self.commit()
        self.git("rm", "tests/old.rs")
        self.head = self.commit()
        result = self.plan()
        self.assertEqual(result["tests"], "true")
        self.assertEqual(result["folder"], "true")
        self.assertEqual(result["debian"], "false")

    def test_newline_and_space_in_filename_are_preserved(self):
        self.write("docs/a b\nc.md", "new docs\n")
        self.head = self.commit()
        self.assertEqual(self.chosen(self.plan()), {"tests"} | cp.ALWAYS)

    def test_three_dot_excludes_changes_only_on_base_branch(self):
        self.write("README.md", "updated docs\n")
        self.head = self.commit()
        self.git("checkout", "-q", self.base)
        self.write("src/service.rs", "fn changed_on_base() {}\n")
        self.base = self.commit()
        self.assertEqual(self.chosen(self.plan()), cp.ALWAYS)

    def test_a_job_the_planner_of_the_base_does_not_know_yet_runs(self):
        old = (HERE / "ci_plan.py").read_text().replace('"debian", "packages", "supply"', '"debian", "supply"')
        old = old.replace('PACKAGES = {"debian", "packages"}', 'PACKAGES = {"debian"}')
        self.assertNotEqual(old, (HERE / "ci_plan.py").read_text())
        self.write(SCRIPT, old)
        self.base = self.commit()
        self.write("README.md", "updated docs\n")
        self.head = self.commit()
        result = self.plan()
        self.assertEqual(self.chosen(result), cp.ALWAYS | {"packages"})
        self.assertEqual(set(result), set(cp.JOBS))

    def test_head_cannot_replace_the_classifier(self):
        # The head's classifier would skip everything. The base's reads the diff,
        # which changes production code and the classifier itself, and selects
        # every job.
        self.write("src/service.rs", "fn service() { changed(); }\n")
        self.write(SCRIPT, "import os\nopen(os.environ['GITHUB_OUTPUT'], 'a').write(''.join(f'{j}=false\\n' for j in "
                           "['lint', 'tests', 'doc', 'msrv', 'debian', 'supply', 'freshness', 'folder', 'lines']))\n")
        self.head = self.commit()
        result = self.plan()
        self.assertEqual(self.chosen(result), set(cp.JOBS))

    def test_missing_or_broken_base_classifier_runs_everything(self):
        for content in (None, "raise RuntimeError('broken base classifier')\n"):
            with self.subTest(content=content):
                if content is None:
                    self.git("rm", SCRIPT)
                else:
                    self.write(SCRIPT, content)
                self.base = self.commit()
                self.head = self.base
                self.assertEqual(set(self.plan().values()), {"true"})

    def test_unreadable_history_runs_everything(self):
        self.assertEqual(set(self.plan(base="f" * 40).values()), {"true"})
        self.assertEqual(set(self.plan(head="f" * 40).values()), {"true"})

    def test_only_a_base_of_exactly_develop_is_planned_from_its_diff(self):
        self.write("README.md", "updated docs\n")
        self.head = self.commit()
        self.assertEqual(self.chosen(self.plan(base_ref="develop")), cp.ALWAYS)
        self.assertEqual(self.chosen(self.plan(base_ref="main")), set(cp.JOBS))
        for base in ("feature", "release/1", "Develop", "develop-2", ""):
            self.assertEqual(self.chosen(self.plan(base_ref=base)), set(cp.JOBS), base)

    def test_nightly_run_selects_only_the_jobs_that_seed_the_caches(self):
        result = self.plan("schedule", base="")
        self.assertEqual({job for job, run in result.items() if run == "true"},
                         {"lint", "tests", "doc", "msrv", "freshness"})

    def test_queue_and_push_do_not_need_a_diff(self):
        self.assertEqual(set(self.plan("push", base="missing").values()), {"true"})
        queue = self.plan("merge_group", base="missing")
        self.assertEqual(self.chosen(queue), set(cp.JOBS) - {"packages"})

    def test_the_package_checks_are_left_out_of_the_queue_only(self):
        self.assertEqual(self.plan("merge_group", base="missing")["packages"], "false")
        self.assertEqual(self.plan("push", base="missing")["packages"], "true")
        self.assertEqual(self.plan(base_ref="main")["packages"], "true")
        self.assertEqual(self.plan("workflow_dispatch", base="missing")["packages"], "true")


class WorkflowContractTests(unittest.TestCase):
    def test_required_callers_have_no_workflow_paths_and_keep_queue_trigger(self):
        for filename in ("ci.yml", "dco.yml"):
            on = workflow(filename)[True]
            self.assertIn("merge_group", on)
            self.assertFalse({"paths", "paths-ignore"} & set(on["pull_request"] or {}))

    def test_each_suite_is_one_exact_call_with_one_exact_condition_and_one_exact_set_of_inputs(self):
        """No presence check: crossing two suites, a fixed `false`, or an extra input turns this red."""
        out = "needs.plan.outputs."
        skip = lambda dim: f"{out}{dim} != 'false'"  # noqa: E731
        first = "(github.event_name != 'pull_request' || needs.line-limit.result != 'failure')"
        spec = {
            "rust": ("reusable-rust-ci.yml",
                     "${{ !cancelled() && " + first + " && (" + " || ".join(skip(d) for d in ("lint", "tests", "doc", "msrv")) + ") }}",
                     {"run-lint": "${{ " + skip("lint") + " }}", "run-tests": "${{ " + skip("tests") + " }}",
                      "run-msrv": "${{ " + skip("msrv") + " }}", "doc-warnings": "${{ " + skip("doc") + " }}",
                      "toolchain": "1.100.0", "msrv": "1.98", "apt-packages": "fakeroot", "coverage-threshold": 88}),
            "debian": ("reusable-rust-debian.yml", "${{ !cancelled() && " + first + " && " + skip("debian") + " }}",
                       {"package-name": "epistle", "run-build": "${{ " + skip("debian") + " }}",
                        "run-tests": "${{ (github.event_name != 'pull_request' && github.event_name != 'merge_group') || github.base_ref == 'main' }}",
                        "rust-toolchain": "1.100.0", "rust-target": "x86_64-unknown-linux-musl",
                        "apt-packages": "musl-tools fakeroot jq", "upload-artifact": True, "artifact-name": "packaging-deb"}),
            "sbom-and-licenses": ("reusable-rust-supply-chain.yml", "${{ !cancelled() && " + first + " && " + skip("supply") + " }}",
                                  {"run-sbom": "${{ " + skip("supply") + " }}"}),
            "line-limit": ("reusable-line-limit.yml", "${{ !cancelled() }}", None),
            "audit": ("reusable-rust-audit.yml", "${{ !cancelled() }}", {"ref": "", "extra-lockfiles": "fuzz/Cargo.lock"}),
        }
        jobs = workflow("ci.yml")["jobs"]
        self.assertEqual(jobs["plan"]["uses"], "./.github/workflows/reusable-ci-plan.yml")
        for job_id, (reusable, condition, inputs) in spec.items():
            job = jobs[job_id]
            self.assertEqual(job["uses"], f"./.github/workflows/{reusable}", job_id)
            self.assertEqual(job["if"], condition, job_id)
            if inputs is None or job_id == "audit":
                self.assertNotIn("needs", job, job_id)
                if inputs is None:
                    self.assertNotIn("with", job, job_id)
                else:
                    self.assertEqual(job["with"], inputs, job_id)
                continue
            self.assertEqual(job["needs"], ["plan", "line-limit"], job_id)
            with_ = dict(job["with"])
            # Checked by their own tests: the long exclusion regex and the pinned image.
            with_.pop({"rust": "coverage-ignore-regex", "debian": "debian-image"}.get(job_id, ""), None)
            self.assertEqual(with_, inputs, job_id)
        self.assertEqual(jobs["debian"]["with"]["debian-image"][:13], "debian:sid@sh")

    def test_the_package_checks_wait_for_the_deb_and_run_only_when_the_plan_selects_them(self):
        job = workflow("ci.yml")["jobs"]["packages"]
        self.assertEqual(job["needs"], ["plan", "debian"])
        self.assertEqual(job["if"], "${{ !cancelled() && needs.debian.result == 'success' && needs.plan.outputs.packages != 'false' }}")
        for step in job["steps"]:
            self.assertFalse({"if", "continue-on-error"} & set(step), step.get("name"))
        runs = " ".join(step.get("run", "") for step in job["steps"])
        for script in ("distro_packages/pack-rpm.sh", "rpm/verify-rpm.sh", "rpm/admission.sh",
                       "distro_packages/pack-pacman.sh", "pacman/admission.sh"):
            self.assertIn(script, runs)

    def test_test_check_reflects_suite_failure_and_cancellation(self):
        test = workflow("reusable-rust-ci.yml")["jobs"]["test"]
        self.assertEqual(test["needs"], ["test-suite", "coverage"])
        self.assertIn("always()", test["if"])
        self.assertIn("needs.coverage.result", test["steps"][0]["env"]["RESULT"])
        for result in ("success", "failure", "cancelled", "skipped", ""):
            done = subprocess.run(["bash", "-c", test["steps"][0]["run"]],
                                  env={**os.environ, "RESULT": result}, capture_output=True)
            self.assertEqual(done.returncode == 0, result == "success")

    def test_coverage_and_plain_suite_are_mutually_exclusive(self):
        jobs = workflow("reusable-rust-ci.yml")["jobs"]
        wait = "!cancelled() && (github.event_name != 'pull_request' || needs.lint.result != 'failure') && "
        self.assertEqual(jobs["test-suite"]["if"], "${{ " + wait + "inputs.run-tests && inputs.coverage-threshold == 0 }}")
        self.assertEqual(jobs["coverage"]["if"], "${{ " + wait + "inputs.run-tests && inputs.coverage-threshold > 0 }}")
        self.assertEqual(jobs["test-extra"]["if"], "${{ " + wait + "inputs.run-tests && inputs.extra-test-os != '[]' }}")
        for name in ("test-suite", "coverage", "test-extra"):
            self.assertEqual(jobs[name]["needs"], "lint", name)
        self.assertIn("cargo test --locked --all-features --workspace", str(jobs["test-suite"]))
        self.assertIn("cargo llvm-cov --locked --workspace --all-features", str(jobs["coverage"]))

    def test_optional_reflectors_skip_unselected_work_too(self):
        jobs = workflow("reusable-rust-ci.yml")["jobs"]
        self.assertEqual(jobs["extra-platforms-gate"]["if"], "${{ always() && inputs.run-tests }}")
        self.assertEqual(jobs["msrv-gate"]["if"], "${{ always() && inputs.run-msrv }}")

    def test_debian_only_opts_out_of_duplicate_suite_on_pr_and_queue(self):
        # Compat 13+ makes dh skip the override itself for nocheck builds;
        # debian/rules calls cargo directly instead of calling dh_auto_test.
        control = (ROOT / "debian/control").read_text()
        compat = re.search(r"debhelper-compat\s*\(=\s*(\d+)\)", control)
        self.assertIsNotNone(compat)
        self.assertGreaterEqual(int(compat[1]), 13)
        caller = workflow("ci.yml")["jobs"]["debian"]["with"]
        # The promotion into main runs the tests too: the package build is the
        # one run as root, and a test that needs a permission bit must fail
        # before the tag, not after it.
        self.assertEqual(
            caller["run-tests"],
            "${{ (github.event_name != 'pull_request' && github.event_name != 'merge_group') || github.base_ref == 'main' }}",
        )
        reusable = workflow("reusable-rust-debian.yml")
        self.assertIs(reusable[True]["workflow_call"]["inputs"]["run-tests"]["default"], True)
        build = next(s for s in reusable["jobs"]["build"]["steps"] if s.get("name") == "Build the package")
        self.assertEqual(build["env"]["DEB_BUILD_OPTIONS"], "${{ !inputs.run-tests && 'nocheck' || '' }}")

    def test_planner_concurrency_does_not_cancel_queue_or_other_callers(self):
        for filename in ("reusable-version-bump.yml", "reusable-ci-plan.yml"):
            concurrency = workflow(filename)["concurrency"]
            self.assertIn("github.workflow", concurrency["group"])
            self.assertIn("github.ref", concurrency["group"])
            self.assertEqual(concurrency["cancel-in-progress"], "${{ github.event_name == 'pull_request' }}")


if __name__ == "__main__":
    unittest.main()
