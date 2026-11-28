"""The pack scripts run with stand-ins for the builders and the checks: what they refuse by themselves."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent

BUILDER = """#!/usr/bin/env bash
# build-rpm.sh STAGE OUT VERSION ARCH, with no container: the content is the same on every call, or counts them.
mkdir -p "$2"
echo call >>"$CALLS"
content="package $3 $4"
[ -z "${DIFFERS:-}" ] || content="$content $(wc -l <"$CALLS")"
echo "$content" >"$2/epistle-$3-1.glyndor.any.$4.rpm"
"""


class PackRpm(unittest.TestCase):
    def run_pack(self, arch="x86_64", **env):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            scripts = tmp / ".github/scripts/distro_packages"
            scripts.mkdir(parents=True)
            shutil.copy(HERE / "pack-rpm.sh", scripts / "pack-rpm.sh")
            (scripts / "stage_payload.py").write_text("")
            (scripts / "build-rpm.sh").write_text(BUILDER)
            for check in ("payload/verify-matches-deb.sh", "rpm/verify-rpm.sh"):
                path = tmp / "tests/packaging" / check
                path.parent.mkdir(parents=True)
                path.write_text(f'echo "{check} $*" >>"$CHECKS"\n')
            done = subprocess.run(
                ["bash", str(scripts / "pack-rpm.sh"), str(tmp / "x.deb"), "1.2.3", arch, str(tmp / "work")],
                capture_output=True, text=True, check=False,
                env={**os.environ, "CALLS": str(tmp / "calls"), "CHECKS": str(tmp / "checks"), **env},
            )
            checks = (tmp / "checks").read_text() if (tmp / "checks").exists() else ""
            return done.returncode, done.stdout + done.stderr, checks

    def test_a_build_that_repeats_is_checked(self):
        for arch in ("x86_64", "aarch64"):
            code, out, checks = self.run_pack(arch)
            self.assertEqual(code, 0, out)
            self.assertIn("rpm/verify-rpm.sh", checks)
            self.assertIn(f"epistle-1.2.3-1.glyndor.any.{arch}.rpm", checks)
        self.assertIn("epistle-1.2.4-1.glyndor.any.x86_64.rpm", self.run_pack()[2], "the later version to upgrade to")

    def test_two_builds_that_differ_stop_before_the_package_is_checked(self):
        code, out, checks = self.run_pack(DIFFERS="1")
        self.assertEqual(code, 1, out)
        self.assertIn("two builds of the same payload differ", out)
        self.assertNotIn("rpm/verify-rpm.sh", checks)

    def test_an_architecture_it_does_not_know_is_refused(self):
        code, out, checks = self.run_pack("armv7")
        self.assertEqual((code, checks), (1, ""), out)


if __name__ == "__main__":
    unittest.main()
