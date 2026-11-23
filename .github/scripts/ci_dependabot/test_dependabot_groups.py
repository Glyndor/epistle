"""Every Dependabot entry ends with a group that takes what the groups before it leave out."""

import unittest
from pathlib import Path

import ci_yaml

CONFIG = Path(__file__).resolve().parents[2] / "dependabot.yml"


def updates():
    return ci_yaml.load(CONFIG)["updates"]


class Groups(unittest.TestCase):
    def test_docker_ends_with_a_group_that_takes_digest_only_bumps(self):
        docker = next(u for u in updates() if u["package-ecosystem"] == "docker")
        names = list(docker["groups"])
        self.assertEqual(names[-1], "images-digests")
        last = docker["groups"]["images-digests"]
        self.assertEqual(last["patterns"], ["*"])
        self.assertNotIn("update-types", last, "a digest bump has no semver level")

    def test_the_mail_base_group_still_comes_first(self):
        docker = next(u for u in updates() if u["package-ecosystem"] == "docker")
        self.assertEqual(list(docker["groups"])[0], "distroless-base")

    def test_every_entry_has_groups_and_the_type_label(self):
        for update in updates():
            name = update["package-ecosystem"]
            self.assertTrue(update.get("groups"), name)
            self.assertTrue(any(label.startswith("type:") for label in update["labels"]), name)

    def test_a_major_bump_of_a_crate_or_an_action_never_joins_the_group_of_minor_and_patch(self):
        for update in updates():
            if update["package-ecosystem"] in {"cargo", "github-actions", "pip"}:
                for name, group in update["groups"].items():
                    kinds = group.get("update-types")
                    self.assertTrue(kinds, f"{update['package-ecosystem']}: {name} would take majors")
                    if "major" in kinds:
                        self.assertEqual(kinds, ["major"], f"{update['package-ecosystem']}: {name} mixes majors with the rest")


if __name__ == "__main__":
    unittest.main()
