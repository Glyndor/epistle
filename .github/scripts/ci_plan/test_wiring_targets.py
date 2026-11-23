"""Which Rust tests read `.github`, found from the tree and not kept by hand."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location("wiring_targets", HERE / "wiring_targets.py")
wt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wt)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, path, text=""):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def manifest(self, **targets):
        self.write("Cargo.toml", "".join(f'[[test]]\nname = "{n}"\npath = "{p}"\n' for n, p in targets.items()))
        self.write("src/lib.rs", "")

    def picked(self):
        return wt.render(self.root)


class TargetSelection(Fixture):
    def test_a_target_that_names_github_is_selected_and_one_that_does_not_is_not(self):
        self.manifest(reads="tests/reads.rs", plain="tests/plain.rs")
        self.write("tests/reads.rs", 'fn t() { read(".github/workflows/ci.yml"); }\n')
        self.write("tests/plain.rs", "fn t() {}\n")
        self.assertEqual(self.picked()["tests"], "--test reads")

    def test_a_file_pulled_in_with_mod_or_path_counts_for_its_target(self):
        self.manifest(viamod="tests/a/viamod.rs", viapath="tests/b/viapath.rs", nested="tests/c/nested.rs")
        self.write("tests/a/viamod.rs", "mod helper;\n")
        self.write("tests/a/helper.rs", 'const X: &str = ".github/dependabot.yml";\n')
        self.write("tests/b/viapath.rs", '#[path = "sub/walk.rs"]\nmod walk;\n')
        self.write("tests/b/sub/walk.rs", 'const X: &str = ".github";\n')
        self.write("tests/c/nested.rs", "mod one;\n")
        self.write("tests/c/nested/one.rs", "mod two;\n")
        self.write("tests/c/nested/two.rs", 'const X: &str = ".github";\n')
        self.assertEqual(self.picked()["tests"], "--test nested --test viamod --test viapath")

    def test_the_repository_wide_tests_are_always_selected(self):
        self.manifest(paths="tests/repository/paths.rs", other="tests/other.rs")
        self.write("tests/repository/paths.rs", "fn t() {}\n")
        self.write("tests/other.rs", "fn t() {}\n")
        self.assertEqual(self.picked()["tests"], "--test paths")

    def test_a_unit_test_is_selected_by_its_module_path_unless_it_only_mentions_github_in_a_comment(self):
        self.manifest()
        self.write("src/db/tests/base.rs", 'fn t() { read(".github/workflows/db.yml"); }\n')
        self.write("src/db/mod.rs", 'fn t() { read(".github/workflows/x.yml"); }\n')
        self.write("src/cli/doc.rs", "/// see .github/workflows\n// and .github again\nfn f() {}\n")
        self.assertEqual(self.picked()["lib"], "db db::tests::base")

    def test_a_name_outside_the_alphabet_is_refused(self):
        self.manifest(**{"bad name": "tests/bad.rs"})
        self.write("tests/bad.rs", ".github")
        with self.assertRaises(ValueError):
            self.picked()

    def test_nothing_is_selected_from_a_tree_that_reads_nothing(self):
        self.manifest()
        self.assertEqual(self.picked(), {"tests": "", "lib": ""})


class ThisRepository(unittest.TestCase):
    """The tree this runs in: the tests that must be on the list are on it."""

    def test_the_tests_that_read_workflows_and_dependabot_are_selected(self):
        picked = wt.render(ROOT)
        names = picked["tests"].split("--test ")
        for name in ("workflow_toolchain_pins", "msrv_agrees_with_ci", "dependabot_config",
                     "workflow_runner_variable", "workflow_coverage_ignore_regex",
                     "repository_paths_exist", "test_discovery_premise"):
            self.assertIn(name, [n.strip() for n in names], name)
        self.assertIn("db::tests::base", picked["lib"].split())

    def test_every_integration_test_that_names_github_is_declared_in_the_manifest(self):
        # A test file that no [[test]] entry names is never run by cargo, so the
        # list could not select it: the premise this list stands on.
        manifest = wt.tomllib.loads((ROOT / "Cargo.toml").read_text())
        declared = {(ROOT / t["path"]).resolve() for t in manifest["test"]}
        reachable = set()
        for path in declared:
            reachable |= wt.sources(path)
        for path in sorted((ROOT / "tests").rglob("*.rs")):
            if wt.MENTION.search(path.read_text(errors="replace")):
                self.assertIn(path.resolve(), reachable, f"{path.relative_to(ROOT)} is read by no test target")


if __name__ == "__main__":
    unittest.main()
