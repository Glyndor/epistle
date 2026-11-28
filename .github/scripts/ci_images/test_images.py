"""The images the workflows and the package builders run are the ones of the Dockerfile Dependabot watches, and each side is checked against the other."""

import re
import shutil
import tempfile
import unittest
from pathlib import Path

import ci_yaml
from ci_images import images

ROOT = Path(__file__).resolve().parents[3]
D = "a" * 64
E = "b" * 64
F = "c" * 64


class TheTree(unittest.TestCase):
    def test_every_image_of_a_workflow_is_the_one_of_the_dockerfile_and_every_line_is_used(self):
        self.assertEqual(images.problems(), [])

    def test_every_image_of_the_package_builders_is_pinned_with_a_tag_and_a_digest_and_is_read(self):
        """A value with no digest is not a reference, so the comparison above would never see it."""
        env = ROOT / images.OTHERS[0]
        values = re.findall(r'^[A-Z_]+_(?:BASE|IMAGE)="([^"]*)"$', env.read_text(), re.M)
        self.assertGreaterEqual(len(values), 2)
        self.assertEqual(len(values), len(re.findall(r"^[A-Z_]+_(?:BASE|IMAGE)=", env.read_text(), re.M)))
        for value in values:
            found = images.REFERENCE.fullmatch(value)
            self.assertTrue(found and found["tag"], value)
        self.assertEqual(len([r for r in images.references() if r[0] == env]), len(values))

    def test_the_dockerfile_is_in_the_docker_entry_of_dependabot_and_the_digest_group_takes_it(self):
        docker = next(u for u in ci_yaml.load(ROOT / ".github/dependabot.yml")["updates"] if u["package-ecosystem"] == "docker")
        self.assertIn("/.github/ci-images", docker["directories"])
        self.assertIn("images-digests", docker["groups"])

    def test_the_dockerfile_builds_nothing_and_holds_only_pinned_from_lines(self):
        entries = images.dockerfile()
        self.assertGreaterEqual(len(entries), 6)
        for name, tag, digest, alias in entries:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertTrue(alias, name)
        self.assertEqual(sorted(a for *_, a in entries), sorted(set(a for *_, a in entries)))


class Attacks(unittest.TestCase):
    """A small tree: one Dockerfile, one workflow."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / ".github/ci-images").mkdir(parents=True)

    def tree(self, dockerfile, workflow):
        (self.root / ".github/ci-images/Dockerfile").write_text(dockerfile)
        (self.root / ".github/workflows/w.yml").write_text(workflow)
        return images.problems(self.root, self.root / ".github/ci-images/Dockerfile")

    def test_agreement_with_and_without_a_tag_and_a_registry_prefix(self):
        docker = f"FROM docker.io/library/rust:1.100-slim@sha256:{D} AS r\nFROM postgres:18@sha256:{E} AS p\n"
        work = f"    container: docker.io/library/rust@sha256:{D} # 1.100-slim\n    image: postgres:18@sha256:{E}\n"
        self.assertEqual(self.tree(docker, work), [])

    def test_a_workflow_that_drifted_a_digest_a_line_nobody_runs_and_an_unlisted_image_are_each_reported(self):
        docker = f"FROM postgres:18@sha256:{D} AS p\nFROM debian:sid@sha256:{E} AS d\n"
        found = self.tree(docker, f"    image: postgres:18@sha256:{F}\n    other: redis:7@sha256:{F}\n")
        self.assertEqual(len(found), 3, found)
        self.assertIn("runs postgres:18 at sha256:cccccccccccc and the Dockerfile has sha256:aaaaaaaaaaaa", found[0])
        self.assertIn("redis:7", found[1])
        self.assertIn("lists debian:sid", found[2])

    def test_the_file_of_the_package_builders_is_compared_both_ways_and_synced(self):
        docker = f"FROM docker.io/library/fedora:45@sha256:{D} AS q\n"
        env = self.root / images.OTHERS[0]
        env.parent.mkdir(parents=True)
        env.write_text(f'# fedora:44@sha256:{E} is only named in a comment\nQUERY_IMAGE="docker.io/library/fedora:45@sha256:{D}"\n')
        self.assertEqual(self.tree(docker, ""), [])
        env.write_text(f'QUERY_IMAGE="docker.io/library/fedora:45@sha256:{F}"\n')
        found = self.tree(docker, "")
        self.assertTrue(len(found) == 1 and "images.env runs fedora:45" in found[0], found)
        images.sync(self.root, self.root / ".github/ci-images/Dockerfile")
        self.assertEqual(env.read_text(), f'QUERY_IMAGE="docker.io/library/fedora:45@sha256:{D}"\n')
        env.unlink()
        self.assertTrue(any("nothing runs it" in line for line in self.tree(docker, "")))

    def test_two_tags_of_one_name_are_told_apart_and_a_tagless_reference_to_them_is_ambiguous(self):
        docker = f"FROM debian:sid@sha256:{D} AS a\nFROM debian:trixie@sha256:{E} AS b\n"
        self.assertEqual(self.tree(docker, f"x: debian:sid@sha256:{D}\ny: debian:trixie@sha256:{E}\n"), [])
        found = self.tree(docker, f"x: debian@sha256:{D}\n")
        self.assertTrue(any("more than one line" in line for line in found), found)

    def test_a_line_that_is_not_a_pinned_from_is_an_error_and_not_skipped(self):
        for bad in ("FROM debian:sid AS a\n", "RUN true\n", f"FROM debian@sha256:{D} AS a\nFROM debian@sha256:{E} AS b\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.tree(bad, "")

    def test_sync_copies_the_digests_of_the_dockerfile_and_touches_nothing_else(self):
        docker = f"FROM postgres:18@sha256:{D} AS p\n"
        work = f"a: postgres:18@sha256:{F} # keep\nb: other@sha256:{F}\nc: cargo-deny-sha256: {F}\n"
        self.tree(docker, work)
        changed = images.sync(self.root, self.root / ".github/ci-images/Dockerfile")
        self.assertEqual([p.name for p in changed], ["w.yml"])
        text = (self.root / ".github/workflows/w.yml").read_text()
        self.assertEqual(text, f"a: postgres:18@sha256:{D} # keep\nb: other@sha256:{F}\nc: cargo-deny-sha256: {F}\n")
        self.assertEqual(images.sync(self.root, self.root / ".github/ci-images/Dockerfile"), [])


if __name__ == "__main__":
    unittest.main()
