"""The CodeQL configuration leaves out test code and only test code, judged by the compiler.

What the production build reads is whatever `rustc` says it read: the dep-info of
`cargo check --lib --bins` (the check itself, `check_paths.py`, runs in the lint job, which
already builds, and reuses its `target`). Here the pieces are tested: the configuration has
nothing but a name and the paths, the patterns mean what CodeQL's documentation says, the
reader of dep-info reads what the compiler writes, and small crates built here with the real
`cargo` show that a file brought in by `include!`, by `#[path]` under `cfg_attr`, or as the
build script of a manifest counts as production.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import ci_yaml
from ci_codeql import check_paths, dep_info, globs

ROOT = Path(__file__).resolve().parents[3]
CONFIG = ROOT / ".github/codeql/codeql-config.yml"
WORKFLOW = ROOT / ".github/workflows/codeql.yml"
# Production code the alerts we know are about, which the analysis has to keep seeing.
PRODUCTION_WITH_AN_ALERT = ("src/api/oauth/mod.rs",)
CARGO = shutil.which("cargo")


def config():
    return ci_yaml.load(CONFIG)


class Configuration(unittest.TestCase):
    def test_it_holds_a_name_and_the_paths_to_ignore_and_nothing_that_narrows_the_queries(self):
        self.assertEqual(set(config()), {"name", "paths-ignore"})
        for forbidden in ("query-filters", "queries", "disable-default-queries", "packs", "paths", "threat-models"):
            self.assertNotIn(forbidden, config())

    def test_the_patterns_are_plain_and_use_only_what_the_documentation_supports(self):
        for pattern in config()["paths-ignore"]:
            self.assertIsInstance(pattern, str)
            for char in "?+[]!":
                self.assertNotIn(char, pattern, f"{char!r} is matched literally, not as a pattern")
            self.assertFalse(pattern.startswith("/") or ".." in pattern, pattern)
            self.assertTrue(pattern.endswith((".rs", "/**")), f"{pattern} would leave out more than rust test code")
            self.assertTrue(pattern.startswith(("src/", "tests/")), pattern)

    def test_no_pattern_hides_the_files_of_the_known_production_alerts(self):
        for path in PRODUCTION_WITH_AN_ALERT:
            for pattern in config()["paths-ignore"]:
                self.assertFalse(globs.matches(pattern, path), f"{pattern} hides {path}")

    def test_both_languages_read_the_configuration(self):
        steps = ci_yaml.load(WORKFLOW)["jobs"]["analyze"]["steps"]
        init = next(s for s in steps if str(s.get("uses", "")).startswith("github/codeql-action/init@"))
        self.assertEqual(init["with"]["config-file"], "./.github/codeql/codeql-config.yml")
        self.assertEqual(init["with"]["languages"], "${{ matrix.language }}")

    def test_a_job_of_its_own_judges_with_the_dep_info_of_five_builds_and_the_sentinel_waits_for_it(self):
        reusable = ci_yaml.load(ROOT / ".github/workflows/reusable-rust-ci.yml")["jobs"]
        job = reusable["codeql-paths"]
        self.assertEqual(job["if"], "inputs.run-lint")
        self.assertIn("codeql-paths", reusable["sentinel"]["needs"])
        steps = {s.get("name"): s for s in job["steps"]}
        builds = steps["Check the production targets and the tests"]["run"]
        expected = (
            "cargo check --locked --lib --bins --message-format=json",
            "cargo check --locked --lib --bins --all-features --message-format=json",
            "cargo check --locked --lib --bins --release --message-format=json",
            "cargo check --locked --lib --bins --release --all-features --message-format=json",
            "cargo check --locked --tests --all-features --message-format=json",
        )
        for line in expected:
            self.assertIn(line + ' > "$out/', builds)
        self.assertEqual(builds.count("cargo check"), len(expected))
        judge = steps["The CodeQL configuration leaves out only files that only the tests read"]["run"]
        self.assertIn("ci_codeql/check_paths.py .github/codeql/codeql-config.yml", judge)
        self.assertLess(judge.index("--production"), judge.index("--tests"))
        # Nothing of this is in the lint job any more, which the later jobs wait for.
        self.assertNotIn("check_paths", str(reusable["lint"]))
        self.assertEqual(reusable["lint"]["timeout-minutes"], 15)


class TheGlobs(unittest.TestCase):
    def test_the_patterns_mean_what_the_documentation_says(self):
        self.assertTrue(globs.matches("src/**/tests/**", "src/a/b/tests/c/d.rs"))
        self.assertTrue(globs.matches("src/**/tests/**", "src/tests/c.rs"))
        self.assertFalse(globs.matches("src/**/tests/**", "src/a/tests.rs"))
        self.assertFalse(globs.matches("src/**/tests/**", "src/contests/a.rs"))
        self.assertTrue(globs.matches("src/**/tests_*.rs", "src/dns/tests_wire.rs"))
        self.assertFalse(globs.matches("src/**/tests_*.rs", "src/dns/sub/x/tests_wire.rs.bak"))
        self.assertFalse(globs.matches("src/*.rs", "src/a/b.rs"))
        self.assertTrue(globs.matches("tests/**", "tests/smtp/hostile.rs"))
        self.assertFalse(globs.matches("tests/**", "src/tests/hostile.rs"))


class DepInfoReading(unittest.TestCase):
    def test_a_rule_with_escaped_spaces_and_phony_targets_lists_each_file_once_as_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.d"
            path.write_text("/t/x.d: src/lib.rs src/a\\ b.rs ../tests/x.rs\n\nsrc/lib.rs:\n\nsrc/a\\ b.rs:\n\n# env-dep:K=V\n")
            self.assertEqual(dep_info.read(path), ["src/lib.rs", "src/a b.rs", "../tests/x.rs"])

    def test_a_line_that_is_not_a_rule_is_an_error_and_not_a_shorter_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.d"
            path.write_text("src/lib.rs src/a.rs\n")
            with self.assertRaises(dep_info.DepInfoError):
                dep_info.read(path)

    def test_no_unit_or_no_dep_info_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(dep_info.DepInfoError):
                dep_info.production_files(['{"reason":"build-finished","success":true}'], tmp)
            (Path(tmp) / "src").mkdir()
            (Path(tmp) / "src/lib.rs").write_text("")
            artifact = {"reason": "compiler-artifact", "target": {"src_path": f"{tmp}/src/lib.rs", "kind": ["lib"]},
                        "profile": {"test": False}, "filenames": [f"{tmp}/target/debug/deps/libx-1.rmeta"]}
            with self.assertRaises(dep_info.DepInfoError):
                dep_info.production_files([json.dumps(artifact)], tmp)  # no .d next to the output
            deps = Path(tmp) / "target/debug/deps"
            deps.mkdir(parents=True)
            (deps / "x-1.d").write_text("")
            with self.assertRaises(dep_info.DepInfoError):
                dep_info.production_files([json.dumps(artifact)], tmp)  # an empty one

    def test_a_test_unit_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = {"reason": "compiler-artifact", "target": {"src_path": f"{tmp}/src/lib.rs", "kind": ["lib"]},
                        "profile": {"test": True}, "filenames": []}
            with self.assertRaises(dep_info.DepInfoError):
                dep_info.production_files([json.dumps(artifact)], tmp)


class Judgment(unittest.TestCase):
    def test_a_pattern_over_production_over_nothing_or_over_what_no_test_build_reads_is_reported(self):
        files = ["src/lib.rs", "src/a/tests/x.rs", "tests/t.rs", "src/ñandú/tests.rs", "src/win/tests_windows.rs"]
        production = {"src/lib.rs", "src/a/tests/x.rs"}
        tests = {"src/lib.rs", "tests/t.rs", "src/ñandú/tests.rs"}
        found = check_paths.problems(["src/**/tests/**", "tests/**", "src/nothing/**", "src/**/tests.rs", "src/**/tests_*.rs"], production, tests, files)
        self.assertEqual(len(found), 3, found)
        self.assertIn("src/**/tests/**", found[0])
        self.assertIn("is read by a production build", found[0])
        self.assertIn("dead pattern", found[1])
        self.assertIn("src/nothing/**", found[1])
        self.assertIn("src/**/tests_*.rs", found[2])
        self.assertIn("nothing proves it is only tests", found[2])

    def test_a_file_that_is_not_rust_needs_no_proof_and_the_arguments_are_split_by_flag(self):
        files = ["tests/fixtures/key.pem", "tests/t.rs"]
        self.assertEqual(check_paths.problems(["tests/**"], set(), {"tests/t.rs"}, files), [])
        self.assertEqual(check_paths.split(["--production", "a", "b", "--tests", "c"]), {"--production": ["a", "b"], "--tests": ["c"]})
        for bad in (["a"], ["--production", "a"], ["--tests", "c"]):
            self.assertIsNone(check_paths.split(bad))

    def test_a_name_that_is_not_ascii_is_listed_whole_by_git_with_a_nul_separator(self):
        with tempfile.TemporaryDirectory() as tmp:
            for cmd in (["init", "-q"], ["config", "user.email", "t@x"], ["config", "user.name", "t"]):
                subprocess.run(["git", *cmd], cwd=tmp, check=True)
            names = ["src/ñandú/tests.rs", "src/with space.rs", "src/new\nline.rs"]
            for name in names:
                path = Path(tmp) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("")
                subprocess.run(["git", "add", "--", name], cwd=tmp, check=True)
            self.assertEqual(sorted(check_paths.tracked(tmp)), sorted(names))
            self.assertEqual(check_paths.problems(["src/**/tests.rs"], set(), {"src/ñandú/tests.rs"}, check_paths.tracked(tmp)), [])


@unittest.skipUnless(CARGO or os.environ.get("CI"), "cargo is not installed")
class TheCompilerIsTheJudge(unittest.TestCase):
    """Small crates built here with the real cargo; the lists are what rustc read."""

    def setUp(self):
        self.assertIsNotNone(CARGO, "cargo is needed in CI to run these")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def crate(self, manifest_extra="", files=None):
        self.write("Cargo.toml", f'[package]\nname = "mini"\nversion = "0.1.0"\nedition = "2021"\n{manifest_extra}\n')
        for name, text in (files or {}).items():
            self.write(name, text)

    def cargo_check(self, *flags):
        done = subprocess.run([CARGO, "check", "--offline", "--message-format=json", *flags], cwd=self.root,
                              capture_output=True, text=True, check=False, env={**os.environ, "CARGO_TARGET_DIR": str(self.root / "target")})
        self.assertEqual(done.returncode, 0, done.stderr[-800:])
        return done.stdout.splitlines()

    def production(self, *flags):
        return dep_info.production_files(self.cargo_check("--lib", "--bins", *flags), self.root)

    def built_by_tests(self, *flags):
        return dep_info.production_files(self.cargo_check("--tests", *flags), self.root, tests=True)

    def judged(self, patterns, *production_flags):
        """What the check says about the patterns, with the production passes of the workflow and the test one."""
        production = set().union(*(self.production(*flags) for flags in (production_flags or ((),))))
        return check_paths.problems(patterns, production, self.built_by_tests("--all-features"), [p.relative_to(self.root).as_posix() for p in self.root.rglob("*.rs") if "target" not in p.parts])

    def test_a_module_tree_with_a_cfg_test_module_leaves_the_test_file_out(self):
        self.crate(files={"src/lib.rs": "pub mod a;\n#[cfg(test)]\nmod tests;\n", "src/a.rs": "", "src/tests.rs": ""})
        self.assertEqual(self.production(), {"src/lib.rs", "src/a.rs"})

    def test_include_from_the_library_makes_an_integration_test_file_production(self):
        self.crate(files={"src/lib.rs": 'include!("../tests/x.rs");\n', "tests/x.rs": "pub fn f() {}\n"})
        files = self.production()
        self.assertIn("tests/x.rs", files)
        self.assertEqual(self.judged(["tests/**"]), [
            "tests/** leaves out 1 Rust file(s) whose first is tests/x.rs, which is read by a production build"])

    def test_a_path_under_cfg_attr_not_test_is_production_and_one_under_test_is_not(self):
        self.crate(files={
            "src/lib.rs": '#[cfg_attr(not(test), path = "../tests/prod.rs")]\nmod prod;\n#[cfg(test)]\n#[cfg_attr(test, path = "../tests/only.rs")]\nmod only;\n',
            "tests/prod.rs": "", "tests/only.rs": ""})
        files = self.production()
        self.assertIn("tests/prod.rs", files)
        self.assertNotIn("tests/only.rs", files)

    def test_the_build_script_a_manifest_names_is_read_whatever_it_is_called(self):
        self.crate(manifest_extra='build = "otro.rs"', files={"src/lib.rs": "", "otro.rs": "fn main() {}\n"})
        self.assertIn("otro.rs", self.production())

    def test_a_feature_brings_a_file_only_with_all_features(self):
        self.crate(manifest_extra='[features]\nextra = []', files={"src/lib.rs": '#[cfg(feature = "extra")]\nmod extra;\n', "src/extra.rs": ""})
        self.assertNotIn("src/extra.rs", self.production())
        self.assertIn("src/extra.rs", self.production("--all-features"))

    def test_a_file_that_only_a_release_build_compiles_is_production_and_the_debug_pass_alone_misses_it(self):
        self.crate(files={"src/lib.rs": '#[cfg(not(debug_assertions))]\nmod tests_fast;\n', "src/tests_fast.rs": ""})
        self.assertNotIn("src/tests_fast.rs", self.production())
        self.assertIn("src/tests_fast.rs", self.production("--release"))
        found = self.judged(["src/**/tests_*.rs"], (), ("--release",))
        self.assertEqual(len(found), 1, found)
        self.assertIn("is read by a production build", found[0])

    def test_a_file_for_another_operating_system_that_looks_like_a_test_cannot_be_proven_to_be_one(self):
        self.crate(files={"src/lib.rs": '#[cfg(target_os = "windows")]\nmod tests_windows;\n', "src/tests_windows.rs": ""})
        found = self.judged(["src/**/tests_*.rs"], (), ("--release",))
        self.assertEqual(len(found), 1, found)
        self.assertIn("nothing proves it is only tests", found[0])

    def test_a_file_only_the_test_build_reads_passes_and_a_dead_helper_that_no_target_compiles_does_not(self):
        self.crate(files={"src/lib.rs": '#[cfg(test)]\nmod tests;\n', "src/tests.rs": "", "src/tests_orphan.rs": ""})
        found = self.judged(["src/**/tests.rs", "src/**/tests_*.rs"], (), ("--release",))
        self.assertEqual(len(found), 1, found)
        self.assertIn("tests_orphan.rs", found[0])

    def test_a_binary_and_a_library_are_both_read(self):
        self.crate(files={"src/lib.rs": "", "src/main.rs": "mod cli;\nfn main() {}\n", "src/cli.rs": ""})
        self.assertEqual(self.production(), {"src/lib.rs", "src/main.rs", "src/cli.rs"})


if __name__ == "__main__":
    unittest.main()
