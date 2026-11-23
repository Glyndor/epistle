import importlib.util
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location(
    "check_merge_group_triggers", os.path.join(HERE, "check_merge_group_triggers.py")
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

MG = "  merge_group:\n    types: [checks_requested]\n"

# reusable file -> job names it holds
REUSABLES = {
    "reusable-rust-ci.yml": ["Format & lint", "Test", "Coverage"],
    "reusable-dco.yml": ["Signed-off-by present on every commit"],
    "reusable-line-limit.yml": ["line limit"],
    "reusable-rust-debian.yml": ["dpkg-buildpackage"],
    "reusable-rust-supply-chain.yml": ["SBOM and license attribution"],
}

# caller file -> [(job id, reusable)]
CALLERS = {
    "ci.yml": [
        ("rust", "reusable-rust-ci.yml"),
        ("line-limit", "reusable-line-limit.yml"),
        ("debian", "reusable-rust-debian.yml"),
        ("sbom-and-licenses", "reusable-rust-supply-chain.yml"),
    ],
    "dco.yml": [("dco", "reusable-dco.yml")],
}


def reusable_text(names):
    jobs = "".join(f"  j{i}:\n    name: {n!r}\n    runs-on: ubuntu-latest\n    steps: []\n" for i, n in enumerate(names))
    return f"name: r\non:\n  workflow_call:\njobs:\n{jobs}"


GATE = "  gate:\n    name: CI gate\n    runs-on: ubuntu-latest\n    steps: []\n"


def caller_text(job_id, reusable, mg=MG, extra=None):
    """A caller of one reusable; the CI workflow also carries the gate job."""
    jobs = {job_id: reusable, **(extra or {})}
    body = "".join(f"  {j}:\n    uses: ./.github/workflows/{r}\n" for j, r in jobs.items())
    return f"name: c\non:\n  pull_request:\n{mg}jobs:\n{body}{GATE if job_id == 'rust' else ''}"


class Tree:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.wf = os.path.join(self.tmp.name, ".github", "workflows")
        os.makedirs(self.wf)
        for name, jobs in REUSABLES.items():
            self.write(name, reusable_text(jobs))
        for name, jobs in CALLERS.items():
            (job_id, reusable), *rest = jobs
            self.write(name, caller_text(job_id, reusable, extra=dict(rest)))

    def write(self, name, text):
        with open(os.path.join(self.wf, name), "w") as fh:
            fh.write(text)

    def run(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = mod.main(["x", self.tmp.name])
        return code, out.getvalue()


class MergeGroupTriggers(unittest.TestCase):
    def setUp(self):
        self.tree = Tree()
        self.addCleanup(self.tree.tmp.cleanup)

    def test_complete_tree_passes(self):
        code, out = self.tree.run()
        self.assertEqual(code, 0, out)

    def test_bare_merge_group_passes(self):
        self.tree.write("dco.yml", caller_text("dco", "reusable-dco.yml", "  merge_group:\n"))
        self.assertEqual(self.tree.run()[0], 0)

    def test_missing_trigger_on_required_caller_fails(self):
        self.tree.write("dco.yml", caller_text("dco", "reusable-dco.yml", ""))
        code, out = self.tree.run()
        self.assertEqual(code, 1)
        self.assertIn("dco / Signed-off-by present on every commit", out)
        self.assertIn("no `merge_group` trigger", out)

    def test_wrong_types_fails(self):
        self.tree.write("ci.yml", caller_text("rust", "reusable-rust-ci.yml", "  merge_group:\n    types: [destroyed]\n", extra=dict(CALLERS["ci.yml"][1:])))
        code, out = self.tree.run()
        self.assertEqual(code, 1)
        self.assertIn("without `checks_requested`", out)

    def test_other_workflow_with_merge_group_fails(self):
        self.tree.write("release.yml", "name: r\non:\n  push:\n" + MG + "jobs:\n  x:\n    runs-on: ubuntu-latest\n    steps: []\n")
        code, out = self.tree.run()
        self.assertEqual(code, 1)
        self.assertIn("release.yml", out)
        self.assertIn("emits no check required on develop", out)

    def test_renamed_caller_job_fails(self):
        self.tree.write("ci.yml", caller_text("rust", "reusable-rust-ci.yml", extra={"limit": "reusable-line-limit.yml", "debian": "reusable-rust-debian.yml", "sbom-and-licenses": "reusable-rust-supply-chain.yml"}))
        code, out = self.tree.run()
        self.assertEqual(code, 1)
        self.assertIn("line-limit / line limit", out)
        self.assertIn("has no caller", out)

    def test_renamed_reusable_job_fails(self):
        self.tree.write("reusable-rust-debian.yml", reusable_text(["build"]))
        code, out = self.tree.run()
        self.assertEqual(code, 1)
        self.assertIn("has no job named `dpkg-buildpackage`", out)

    def test_gate_without_the_trigger_fails(self):
        self.tree.write("ci.yml", caller_text("rust", "reusable-rust-ci.yml", "", extra=dict(CALLERS["ci.yml"][1:])))
        code, out = self.tree.run()
        self.assertEqual(code, 1)
        self.assertIn("`CI gate` is required on develop", out)

    def test_renamed_gate_fails(self):
        text = caller_text("rust", "reusable-rust-ci.yml", extra=dict(CALLERS["ci.yml"][1:])).replace("name: CI gate", "name: Gate")
        self.tree.write("ci.yml", text)
        code, out = self.tree.run()
        self.assertEqual(code, 1)
        self.assertIn("required check `CI gate` is not emitted", out)

    def test_gate_that_calls_a_reusable_fails(self):
        text = caller_text("rust", "reusable-rust-ci.yml", extra=dict(CALLERS["ci.yml"][1:])).replace("    runs-on: ubuntu-latest\n    steps: []\n", "    uses: ./.github/workflows/reusable-dco.yml\n")
        self.tree.write("ci.yml", text)
        code, out = self.tree.run()
        self.assertEqual(code, 1)
        self.assertIn("that runs its own steps", out)

    def test_unparsable_file_is_skipped_with_warning(self):
        self.tree.write("broken.yml", "a: [unclosed\n")
        code, out = self.tree.run()
        self.assertEqual(code, 0, out)
        self.assertIn("::warning", out)


if __name__ == "__main__":
    unittest.main()
