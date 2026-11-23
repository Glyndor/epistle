"""The CI files equal their reference copy; a pin may move and nothing else may."""

import copy
import unittest
from pathlib import Path

import ci_contract.contract as contract
import ci_yaml

ROOT = Path(__file__).resolve().parents[3]
SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
OTHER = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "a" * 64


class Equality(unittest.TestCase):
    def test_every_file_equals_its_reference(self):
        for relative in contract.FILES:
            with self.subTest(file=relative):
                self.assertEqual(
                    contract.current(ROOT, relative),
                    contract.reference(ROOT, relative),
                    f"{relative} differs from .github/ci-contract; if on purpose run python3 .github/scripts/ci_contract/snapshot.py",
                )

    def test_the_reference_folder_holds_exactly_these_files(self):
        held = sorted(p.name for p in (ROOT / contract.FOLDER).iterdir())
        self.assertEqual(held, sorted(Path(f).name + ".json" for f in contract.FILES))

    def test_every_workflow_that_calls_or_is_called_by_the_gate_is_in_the_contract(self):
        needed = set()
        for relative in ("ci.yml", "dco.yml", "main-guard.yml"):
            for job in ci_yaml.load(ROOT / ".github/workflows" / relative)["jobs"].values():
                uses = job.get("uses", "")
                if uses.startswith("./.github/"):
                    needed.add(uses[2:])
                for step in job.get("steps", []):
                    uses = str(step.get("uses", ""))
                    if uses.startswith("./.github/"):
                        needed.add(uses[2:].rstrip("/") + "/action.yml")
        self.assertTrue(needed <= set(contract.FILES), sorted(needed - set(contract.FILES)))

    def test_every_external_action_is_pinned_by_commit_in_the_reference(self):
        def walk(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "uses" and isinstance(item, str) and not item.startswith("./"):
                        yield item
                    yield from walk(item)
            elif isinstance(value, list):
                for item in value:
                    yield from walk(item)

        for relative in contract.FILES:
            for uses in walk(contract.reference(ROOT, relative)):
                self.assertTrue(uses.endswith("@PIN"), f"{relative}: {uses}")


class OnlyAPinMoves(unittest.TestCase):
    """Rule 44, in both directions, on the normaliser."""

    def uses(self, value):
        return contract.normalize({"jobs": {"a": {"steps": [{"uses": value}]}}})

    def test_a_new_commit_of_the_same_action_is_the_same_file(self):
        self.assertEqual(self.uses(f"actions/checkout@{SHA}"), self.uses(f"actions/checkout@{OTHER}"))

    def test_a_new_digest_of_the_same_image_is_the_same_file(self):
        a = contract.normalize({"image": f"debian:sid@{DIGEST}"})
        b = contract.normalize({"image": "debian:sid@sha256:" + "b" * 64})
        self.assertEqual(a, b)

    def test_another_action_or_owner_is_another_file(self):
        self.assertNotEqual(self.uses(f"actions/checkout@{SHA}"), self.uses(f"actions/cache@{SHA}"))
        self.assertNotEqual(self.uses(f"actions/checkout@{SHA}"), self.uses(f"someone/checkout@{SHA}"))

    def test_a_dropped_pin_a_tag_or_a_branch_is_another_file(self):
        pinned = self.uses(f"actions/checkout@{SHA}")
        for value in ("actions/checkout", "actions/checkout@v7", "actions/checkout@main", f"actions/checkout@{SHA[:39]}"):
            with self.subTest(value=value):
                self.assertNotEqual(pinned, self.uses(value))

    def test_another_repository_or_tag_of_an_image_is_another_file(self):
        base = contract.normalize({"image": f"debian:sid@{DIGEST}"})
        for value in (f"ubuntu:sid@{DIGEST}", f"debian:trixie@{DIGEST}", "debian:sid", f"debian:sid@{DIGEST[:-1]}"):
            with self.subTest(value=value):
                self.assertNotEqual(base, contract.normalize({"image": value}))

    def test_nothing_but_pins_is_normalised(self):
        for value in ("a: 1", "run: echo hi", "shell: bash", "if: always()"):
            key, text = value.split(": ")
            self.assertEqual(contract.normalize({key: text}), {key: text})
        self.assertEqual(contract.normalize({"a": [True, None, 3, "x"]}), {"a": [True, None, 3, "x"]})

    def test_a_bump_of_a_pin_in_the_real_ci_file_still_equals_the_reference(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        bumped = ci_yaml.loads(text.replace(SHA, OTHER))
        self.assertEqual(contract.normalize(bumped), contract.reference(ROOT, ".github/workflows/ci.yml"))

    def test_an_edit_the_old_checks_would_not_see_is_caught(self):
        base = ci_yaml.load(ROOT / ".github/workflows/ci.yml")
        for edit in (
            lambda d: d["jobs"]["gate"].update({"continue-on-error": True}),
            lambda d: d["jobs"]["gate"]["steps"][0].update({"shell": "bash -c 'exit 0' {0}"}),
            lambda d: d["jobs"]["gate"].update({"defaults": {"run": {"working-directory": "/tmp"}}}),
            lambda d: d.update({"defaults": {"run": {"shell": "true {0}"}}}),
            lambda d: d["jobs"]["rust"]["with"].update({"coverage-threshold": 0}),
        ):
            changed = copy.deepcopy(base)
            self.assertEqual(contract.normalize(changed), contract.reference(ROOT, ".github/workflows/ci.yml"))
            edit(changed)
            self.assertNotEqual(contract.normalize(changed), contract.reference(ROOT, ".github/workflows/ci.yml"))


if __name__ == "__main__":
    unittest.main()
