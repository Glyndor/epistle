"""The script that bumps the version, against the judge that says what a pure bump is."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from version_bump import bump_version
from version_bump.fixtures import GIT_ENV, JUDGE, NEW, OLD, SCRIPT, Repo, read, seed, write

BULLETS = "* A new route.\n* A fix.\n"
DATE = "Tue, 24 Nov 2026 12:00:00 +0000"


def run_script(root, new=NEW, bullets=BULLETS, extra=()):
    path = Path(root).parent / (Path(root).name + "-entry.txt")
    path.write_text(bullets)
    return subprocess.run([sys.executable, "-I", bump_version.__file__, new, "--changelog", str(path), "--date", DATE, "--root", str(root), *extra],
                          capture_output=True, text=True, check=False, env={**os.environ, **GIT_ENV})


class Bump(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        here = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, here)
        seed(judge=True)
        for command in (["init", "-q", "."], ["config", "commit.gpgsign", "false"], ["add", "-A"], ["commit", "-q", "-m", "base"], ["tag", "base"]):
            subprocess.run(["git", *command], cwd=self.root, check=True, capture_output=True, env={**os.environ, **GIT_ENV})

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True, text=True, env={**os.environ, **GIT_ENV}).stdout

    def judge(self):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "bump")
        return subprocess.run([sys.executable, "-I", str(self.root / JUDGE), "base", "HEAD"], cwd=self.root, capture_output=True, text=True, check=False, env={**os.environ, **GIT_ENV})

    def test_the_change_it_makes_is_what_the_judge_calls_a_pure_bump(self):
        done = run_script(self.root)
        self.assertEqual(done.returncode, 0, done.stderr)
        judged = self.judge()
        self.assertEqual((judged.returncode, judged.stdout.strip()), (0, f"a pure version bump: {OLD} -> {NEW}"), judged.stderr)

    def test_each_stamp_moves_and_the_floating_tag_and_the_dependency_stay(self):
        write("Cargo.toml", read("Cargo.toml") + f'reqwest = {{ version = "{OLD}" }}\n')
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "reqwest")
        self.git("tag", "-f", "base")
        self.assertEqual(run_script(self.root).returncode, 0)
        self.assertIn(f'version = "{NEW}"\nedition', read("Cargo.toml"))
        self.assertIn(f'reqwest = {{ version = "{OLD}" }}', read("Cargo.toml"))
        for lock in ("Cargo.lock", "fuzz/Cargo.lock"):
            self.assertIn(f'name = "epistle"\nversion = "{NEW}"', read(lock))
        doc = read("docs/operations/container.md")
        self.assertIn(f"ghcr.io/glyndor/epistle:{NEW}", doc)
        self.assertIn("ghcr.io/glyndor/epistle:0.12`", doc)
        self.assertNotIn(OLD, doc)
        top = read("debian/changelog")
        self.assertTrue(top.startswith(f"epistle ({NEW}) unstable; urgency=medium\n\n  * A new route.\n  * A fix.\n\n -- Glyndor <packages@glyndor.net>  {DATE}\n\nepistle ({OLD}) "), top[:300])

    def test_every_form_of_the_image_tag_of_the_release_moves(self):
        text = f"a ghcr.io/glyndor/epistle:{OLD}\nb `…:{OLD}-arm64`, `ghcr.io/glyndor/epistle:{OLD}-amd64`\nc ghcr.io/glyndor/epistle:{OLD}0 and epistle:{OLD}.1 and ghcr.io/glyndor/epistle:0.{OLD}\n"
        out = bump_version.bump_doc(text, OLD, NEW)
        self.assertIn(f"epistle:{NEW}\n", out)
        self.assertIn(f"`…:{NEW}-arm64`, `ghcr.io/glyndor/epistle:{NEW}-amd64`", out)
        self.assertIn(f"epistle:{OLD}0 and epistle:{OLD}.1 and ghcr.io/glyndor/epistle:0.{OLD}", out)

    def test_it_refuses_and_writes_nothing_when_a_file_is_not_what_it_expects(self):
        cases = {
            "an older version": lambda: run_script(self.root, new="0.12.4"),
            "the same version": lambda: run_script(self.root, new=OLD),
            "not a plain version": lambda: run_script(self.root, new="0.13"),
            "a prerelease": lambda: run_script(self.root, new="0.13.0-rc.1"),
            "a bullet without its mark": lambda: run_script(self.root, bullets="A fix.\n"),
            "no bullet": lambda: run_script(self.root, bullets="\n"),
        }
        for name, call in cases.items():
            with self.subTest(name):
                done = call()
                self.assertEqual(done.returncode, 1, name)
                self.assertIn("not bumped:", done.stderr)
                self.assertEqual(self.git("status", "--short"), "", name)

    def test_a_lockfile_with_two_epistle_packages_or_a_changelog_of_another_version_stops_everything(self):
        write("fuzz/Cargo.lock", read("fuzz/Cargo.lock") + f'\n[[package]]\nname = "epistle"\nversion = "{OLD}"\n')
        done = run_script(self.root)
        self.assertEqual(done.returncode, 1)
        self.assertIn("fuzz/Cargo.lock has 2 packages named epistle", done.stderr)
        self.assertIn(f'version = "{OLD}"', read("Cargo.toml"), "nothing was written")
        write("fuzz/Cargo.lock", read("fuzz/Cargo.lock").split("\n[[package]]\nname = \"epistle\"\nversion")[0] + "\n")
        self.git("checkout", "--", "fuzz/Cargo.lock")
        write("debian/changelog", read("debian/changelog").replace(f"epistle ({OLD})", "epistle (0.12.3)", 1))
        done = run_script(self.root)
        self.assertEqual(done.returncode, 1)
        self.assertIn("not the entry of", done.stderr)

    def test_a_dependency_version_in_the_package_table_position_is_not_taken_for_the_package(self):
        text = '[dependencies]\nversion = "1.0.0"\n[package]\nname = "epistle"\n'
        with self.assertRaises(bump_version.Refused):
            bump_version.package_version(text)


if __name__ == "__main__":
    unittest.main()
