"""The loader refuses duplicate keys, and the enumerator sees every workflow and action."""

import tempfile
import unittest
from pathlib import Path

import yaml

import ci_yaml

ROOT = Path(__file__).resolve().parents[2]


class Loader(unittest.TestCase):
    def test_a_plain_file_loads(self):
        self.assertEqual(ci_yaml.loads("a: 1\nb: [x, y]\n"), {"a": 1, "b": ["x", "y"]})

    def test_a_duplicate_key_is_an_error_at_any_depth(self):
        for text in ("a: 1\na: 2\n", "jobs:\n  x:\n    if: a\n    if: b\n", "- k: 1\n  k: 1\n"):
            with self.subTest(text=text), self.assertRaises(yaml.YAMLError):
                ci_yaml.loads(text)

    def test_the_safe_loader_would_have_taken_the_last_key_silently(self):
        self.assertEqual(yaml.safe_load("a: 1\na: 2\n"), {"a": 2})

    def test_a_python_object_tag_is_refused(self):
        with self.assertRaises(yaml.YAMLError):
            ci_yaml.loads("a: !!python/object/apply:os.system ['true']\n")

    def test_every_workflow_and_action_in_this_tree_parses(self):
        for path in (*ci_yaml.workflow_files(ROOT), *ci_yaml.action_files(ROOT)):
            self.assertIsInstance(ci_yaml.load(path), dict, path)


class Enumerator(unittest.TestCase):
    def tree(self, *names):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for name in names:
            path = Path(tmp.name) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("a: 1\n")
        return Path(tmp.name)

    def test_both_suffixes_and_nested_folders_are_listed(self):
        root = self.tree(".github/workflows/a.yml", ".github/workflows/b.yaml", ".github/workflows/sub/c.yml",
                         ".github/workflows/notes.txt")
        self.assertEqual([p.name for p in ci_yaml.workflow_files(root)], ["a.yml", "b.yaml", "c.yml"])

    def test_actions_are_found_anywhere_with_either_name_and_the_build_dirs_are_skipped(self):
        root = self.tree(".github/actions/x/action.yml", ".github/actions/y/action.yaml", "deploy/z/action.yml",
                         "target/debug/q/action.yml", "vendor/r/action.yml", "docs/action.md")
        self.assertEqual([p.parent.name for p in ci_yaml.action_files(root)], ["x", "y", "z"])

    def test_this_tree_has_the_cache_action(self):
        self.assertIn(ROOT / ".github/actions/rust-cache/action.yml", ci_yaml.action_files(ROOT))


if __name__ == "__main__":
    unittest.main()
