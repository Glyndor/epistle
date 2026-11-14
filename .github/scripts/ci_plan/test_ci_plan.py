"""Selection policy, real Git ranges, and the workflow steps that consume it."""

import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location("planner", HERE / "ci_plan.py")
cp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cp)
SCRIPT = ".github/scripts/ci_plan/ci_plan.py"


def workflow(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


class SelectionTests(unittest.TestCase):
    def selected(self, *paths, status="M", event="pull_request"):
        return {job for job, run in cp.select(event, [(status, p) for p in paths]).items() if run}

    def test_docs_edits_skip_unaffected_work(self):
        self.assertEqual(self.selected("README.md"), set())
        self.assertEqual(self.selected("docs/operations/merge-queue.md"), {"tests"})

    def test_new_docs_only_need_folder_count(self):
        self.assertEqual(self.selected("docs/new.md", status="A"), {"tests", "folder"})

    def test_test_only_changes_keep_suite_and_lint(self):
        for path in ("tests/smtp/hostile.rs", "src/cli/tests/base.rs",
                     "src/imap/session_tests.rs", "src/dns/tests_wire.rs",
                     "src/imap/parse_tests_extra.rs", "src/test_support.rs"):
            with self.subTest(path=path):
                self.assertEqual(self.selected(path), {"lint", "tests", "lines"})

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
        self.assertEqual(self.selected("debian/rules"), {"debian", "tests"})

    def test_folder_gate_only_needs_path_changes_or_its_own_inputs(self):
        for status in ("A", "D"):
            self.assertIn("folder", self.selected("src/imap/x.rs", status=status))
        for path in (".github/folder-limit-exceptions.txt", "scripts/folder-limit/folder-limit.sh"):
            self.assertIn("folder", self.selected(path))

    def test_mixed_change_takes_union(self):
        self.assertEqual(self.selected("README.md", "tests/x.rs", "about.hbs"),
                         {"lint", "tests", "lines", "supply"})

    def test_classifier_and_unknown_paths_run_everything(self):
        for path in (*cp.OWN, "a-new-build-input", ".github/workflows/new-build.yml"):
            self.assertEqual(self.selected(path), set(cp.JOBS))

    def test_non_pr_events_and_empty_diff_run_everything(self):
        for event in ("merge_group", "push", "schedule", "workflow_dispatch", ""):
            self.assertEqual(self.selected("README.md", event=event), set(cp.JOBS))
        self.assertEqual(self.selected(), set(cp.JOBS))

    def test_workflows_and_dependency_config_select_their_consumers(self):
        for filename, jobs in cp.WORKFLOWS.items():
            self.assertTrue(jobs | {"tests"} <= self.selected(f".github/workflows/{filename}"))
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

    def plan(self, event="pull_request", base=None, head=None):
        output = self.repo / "outputs"
        output.write_text("")
        step = workflow("reusable-ci-plan.yml")["jobs"]["plan"]["steps"][-1]["run"]
        done = subprocess.run(["bash", "-c", step], cwd=self.repo,
                              env={**self.env, "EVENT_NAME": event, "BASE_SHA": base or self.base,
                                   "HEAD_SHA": head or self.head, "GITHUB_OUTPUT": str(output),
                                   "RUNNER_TEMP": str(self.repo)}, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return dict(line.split("=", 1) for line in output.read_text().splitlines())

    def test_docs_diff_through_actual_workflow_step(self):
        self.write("README.md", "updated docs\n")
        self.head = self.commit()
        self.assertEqual(set(self.plan().values()), {"false"})

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
        self.assertEqual({job for job, run in self.plan().items() if run == "true"}, {"tests", "folder"})

    def test_three_dot_excludes_changes_only_on_base_branch(self):
        self.write("README.md", "updated docs\n")
        self.head = self.commit()
        self.git("checkout", "-q", self.base)
        self.write("src/service.rs", "fn changed_on_base() {}\n")
        self.base = self.commit()
        self.assertEqual(set(self.plan().values()), {"false"})

    def test_head_cannot_replace_the_classifier(self):
        self.write(SCRIPT, "raise RuntimeError('must not execute head classifier')\n")
        self.head = self.commit()
        self.assertEqual(set(self.plan().values()), {"true"})

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

    def test_queue_and_push_do_not_need_a_diff(self):
        for event in ("merge_group", "push"):
            self.assertEqual(set(self.plan(event, base="missing").values()), {"true"})


class WorkflowContractTests(unittest.TestCase):
    def test_required_callers_have_no_workflow_paths_and_keep_queue_trigger(self):
        for filename in ("ci.yml", "debian.yml", "supply-chain.yml", "line-limit.yml", "dco.yml"):
            on = workflow(filename)[True]
            self.assertIn("merge_group", on)
            self.assertFalse({"paths", "paths-ignore"} & set(on["pull_request"] or {}))

    def test_gated_callers_run_after_a_failed_plan_and_default_to_running(self):
        for filename, job_id, inputs in (
            ("ci.yml", "rust", {"run-lint": "lint", "run-tests": "tests", "run-msrv": "msrv", "doc-warnings": "doc"}),
            ("debian.yml", "debian", {"run-build": "debian"}),
            ("supply-chain.yml", "sbom-and-licenses", {"run-sbom": "supply"}),
            ("line-limit.yml", "line-limit", {"run-check": "lines"}),
        ):
            jobs = workflow(filename)["jobs"]
            self.assertEqual(jobs["plan"]["uses"], "./.github/workflows/reusable-ci-plan.yml")
            job = jobs[job_id]
            self.assertEqual(job["needs"], "plan")
            self.assertEqual(job["if"], "${{ !cancelled() }}")
            for key, output in inputs.items():
                self.assertEqual(job["with"][key], "${{ needs.plan.outputs." + output + " != 'false' }}")

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
        self.assertEqual(jobs["test-suite"]["if"], "inputs.run-tests && inputs.coverage-threshold == 0")
        self.assertEqual(jobs["coverage"]["if"], "inputs.run-tests && inputs.coverage-threshold > 0")
        self.assertIn("cargo test --locked --all-features --workspace", str(jobs["test-suite"]))
        self.assertIn("cargo llvm-cov --locked --workspace --all-features", str(jobs["coverage"]))

    def test_optional_reflectors_skip_unselected_work_too(self):
        jobs = workflow("reusable-rust-ci.yml")["jobs"]
        self.assertEqual(jobs["extra-platforms-gate"]["if"], "${{ always() && inputs.run-tests }}")
        self.assertEqual(jobs["msrv-gate"]["if"], "${{ always() && inputs.run-msrv }}")

    def test_line_extensions_match_the_reusable_defaults(self):
        inputs = workflow("reusable-line-limit.yml")[True]["workflow_call"]["inputs"]
        for extension in inputs["extensions"]["default"].split():
            self.assertIn("lines", SelectionTests().selected(f"docs/sample.{extension}"))

    def test_debian_only_opts_out_of_duplicate_suite_on_pr_and_queue(self):
        # Compat 13+ makes dh skip the override itself for nocheck builds;
        # debian/rules calls cargo directly instead of calling dh_auto_test.
        control = (ROOT / "debian/control").read_text()
        compat = re.search(r"debhelper-compat\s*\(=\s*(\d+)\)", control)
        self.assertIsNotNone(compat)
        self.assertGreaterEqual(int(compat[1]), 13)
        caller = workflow("debian.yml")["jobs"]["debian"]["with"]
        self.assertEqual(caller["run-tests"], "${{ github.event_name != 'pull_request' && github.event_name != 'merge_group' }}")
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
