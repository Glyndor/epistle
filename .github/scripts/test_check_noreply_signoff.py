import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check_noreply_signoff.sh")
NOREPLY = "1+someone@users.noreply.github.com"
PERSONAL = "someone@example.org"


def git(cwd, *args, email=NOREPLY):
    out = subprocess.run(
        ["git", "-c", "user.name=Someone", "-c", f"user.email={email}", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


class NoreplySignoff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        git(self.repo, "init", "-q")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self):
        head = git(self.repo, "rev-parse", "HEAD")
        return subprocess.run(
            ["bash", SCRIPT, self.base, head],
            cwd=self.repo,
            capture_output=True,
            text=True,
        )

    def test_noreply_author_and_signoff_pass(self):
        git(self.repo, "commit", "-q", "--allow-empty", "-s", "-m", "ok")
        self.assertEqual(self.run_check().returncode, 0)

    def test_personal_signoff_fails(self):
        git(self.repo, "commit", "-q", "--allow-empty", "-s", "-m", "bad", email=NOREPLY)
        git(
            self.repo,
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            f"bad\n\nSigned-off-by: Someone <{PERSONAL}>",
        )
        res = self.run_check()
        self.assertEqual(res.returncode, 1)
        self.assertIn(PERSONAL, res.stdout)

    def test_personal_author_fails(self):
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "bad", email=PERSONAL)
        self.assertEqual(self.run_check().returncode, 1)

    def test_personal_co_author_fails(self):
        git(
            self.repo,
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            f"bad\n\nCo-authored-by: Other <{PERSONAL}>",
        )
        self.assertEqual(self.run_check().returncode, 1)

    def test_dependabot_support_address_passes(self):
        git(
            self.repo,
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "bump\n\nSigned-off-by: dependabot[bot] <support@github.com>",
            email="49699333+dependabot[bot]@users.noreply.github.com",
        )
        self.assertEqual(self.run_check().returncode, 0)


if __name__ == "__main__":
    unittest.main()
