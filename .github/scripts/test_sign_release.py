"""sign_release.sh refuses to sign without a key or without its arguments."""
import os
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "sign_release.sh")


def run(*args, env=None):
    clean = {k: v for k, v in os.environ.items() if k != "GLYNDOR_RELEASE_ED25519_KEY"}
    clean.update(env or {})
    return subprocess.run(
        ["bash", SCRIPT, *args], capture_output=True, text=True, env=clean, check=False
    )


class SignReleaseTests(unittest.TestCase):
    def test_no_key_means_no_signature(self):
        with tempfile.TemporaryDirectory() as dist:
            done = run(dist, "v0.0.0")
            self.assertNotEqual(done.returncode, 0)
            self.assertIn("refusing to release unsigned", done.stderr)
            self.assertEqual(os.listdir(dist), [])

    def test_an_empty_key_is_no_key(self):
        with tempfile.TemporaryDirectory() as dist:
            done = run(dist, "v0.0.0", env={"GLYNDOR_RELEASE_ED25519_KEY": ""})
            self.assertNotEqual(done.returncode, 0)
            self.assertEqual(os.listdir(dist), [])

    def test_the_directory_and_the_tag_are_required(self):
        self.assertNotEqual(run().returncode, 0)
        with tempfile.TemporaryDirectory() as dist:
            self.assertNotEqual(run(dist).returncode, 0)

    def test_every_published_file_gets_a_signature(self):
        # The publish job refuses a file with no `.sig`, and the build job
        # makes the binary, the SBOM, SHA256SUMS and the packages. A file that
        # the signer skips only fails once the real release reaches publish.
        root = os.path.join(os.path.dirname(__file__), "..", "..")
        script = open(SCRIPT).read()
        workflow = open(os.path.join(root, ".github", "workflows", "release.yml")).read()
        for name in ('epistle-${tag}-x86_64-linux"', 'epistle-${tag}.cdx.json"', "SHA256SUMS", "epistle_*.deb"):
            self.assertIn(name, script, f"sign_release.sh does not sign {name}")
        self.assertIn('"epistle-${TAG}.cdx.json.sig"', workflow)


if __name__ == "__main__":
    unittest.main()
