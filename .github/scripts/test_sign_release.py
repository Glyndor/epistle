"""sign_release.sh refuses to sign without a key, without its arguments or without exactly the files of the tag."""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "sign_release.sh"
TAG = "v1.2.3"
NAMES = ["SHA256SUMS", f"epistle-{TAG}-x86_64-linux", f"epistle-{TAG}.cdx.json",
         "epistle_1.2.3_amd64.deb", "epistle_1.2.3_arm64.deb"]


def run(*args, env=None):
    clean = {k: v for k, v in os.environ.items() if k != "GLYNDOR_RELEASE_ED25519_KEY"}
    clean.update(env or {})
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=clean, check=False)


class Refusals(unittest.TestCase):
    def test_no_key_means_no_signature(self):
        with tempfile.TemporaryDirectory() as dist:
            done = run("/nonexistent-venv", dist, TAG)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn("refusing to release unsigned", done.stderr)
            self.assertEqual(os.listdir(dist), [])

    def test_an_empty_key_is_no_key(self):
        with tempfile.TemporaryDirectory() as dist:
            done = run("/nonexistent-venv", dist, TAG, env={"GLYNDOR_RELEASE_ED25519_KEY": ""})
            self.assertNotEqual(done.returncode, 0)
            self.assertEqual(os.listdir(dist), [])

    def test_the_venv_the_directory_and_the_tag_are_required(self):
        self.assertNotEqual(run().returncode, 0)
        with tempfile.TemporaryDirectory() as dist:
            self.assertNotEqual(run("/v").returncode, 0)
            self.assertNotEqual(run("/v", dist).returncode, 0)

    def test_a_directory_that_is_not_exactly_the_files_of_the_tag_is_refused_before_the_key_is_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            dist.mkdir()
            (dist / "epistle_999.0.0_amd64.deb").write_text("x")
            log = Path(tmp) / "calls"
            venv = fake_venv(tmp, log)
            done = run(str(venv), str(dist), TAG, env={"GLYNDOR_RELEASE_ED25519_KEY": "k"})
            self.assertNotEqual(done.returncode, 0)
            self.assertFalse(log.exists(), "the signer must not run on a directory that is not the release")


def fake_venv(tmp, log):
    """A virtualenv whose python records the arguments it is given and signs nothing."""
    venv = Path(tmp) / "venv"
    (venv / "bin").mkdir(parents=True)
    python = venv / "bin" / "python"
    python.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\n')
    python.chmod(python.stat().st_mode | stat.S_IEXEC)
    return venv


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb is not installed")
class Signing(unittest.TestCase):
    def test_every_published_file_is_signed_by_explicit_path_in_isolated_mode(self):
        # The publish job refuses a file with no `.sig`. A file the signer skips
        # only fails once the real release reaches publish.
        from release.test_release_files import Directory  # the real directory of a release

        case = Directory("test_the_exact_set_passes")
        case.setUp()
        self.addCleanup(case.tmp.cleanup)
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "calls"
            venv = fake_venv(tmp, log)
            done = run(str(venv), str(case.dist), TAG, env={"GLYNDOR_RELEASE_ED25519_KEY": "k"})
            self.assertEqual(done.returncode, 0, done.stderr)
            calls = log.read_text().splitlines()
        self.assertEqual(sorted(calls), sorted(f"-I {HERE}/sign.py {case.dist}/{name}" for name in NAMES))

    def test_the_script_runs_nothing_from_the_directory_of_the_files(self):
        text = SCRIPT.read_text()
        self.assertNotIn("pip install", text)
        self.assertNotIn("python3 -m", text)
        self.assertIn('"$venv/bin/python" -I', text)
        self.assertIn('cd "$here"', text)


if __name__ == "__main__":
    unittest.main()
