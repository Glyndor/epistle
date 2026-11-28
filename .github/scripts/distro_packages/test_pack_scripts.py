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


PACMAN_BUILDER = """#!/usr/bin/env bash
# build-pacman.sh STAGE OUT VERSION, with no container.
mkdir -p "$2"
echo call >>"$CALLS"
content="package $3"
[ -z "${DIFFERS:-}" ] || content="$content $(wc -l <"$CALLS")"
echo "$content" >"$2/epistle-$3-1-x86_64.pkg.tar.zst"
"""


class PackPacman(unittest.TestCase):
    def run_pack(self, **env):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            scripts = tmp / ".github/scripts/distro_packages"
            scripts.mkdir(parents=True)
            shutil.copy(HERE / "pack-pacman.sh", scripts / "pack-pacman.sh")
            (scripts / "stage_payload.py").write_text("")
            (scripts / "build-pacman.sh").write_text(PACMAN_BUILDER)
            for check in ("payload/verify-matches-deb.sh", "pacman/verify-pacman.sh"):
                path = tmp / "tests/packaging" / check
                path.parent.mkdir(parents=True)
                path.write_text(f'echo "{check} $*" >>"$CHECKS"\n')
            done = subprocess.run(
                ["bash", str(scripts / "pack-pacman.sh"), str(tmp / "x.deb"), "1.2.3", str(tmp / "work")],
                capture_output=True, text=True, check=False,
                env={**os.environ, "CALLS": str(tmp / "calls"), "CHECKS": str(tmp / "checks"), **env},
            )
            checks = (tmp / "checks").read_text() if (tmp / "checks").exists() else ""
            return done.returncode, done.stdout + done.stderr, checks

    def test_a_build_that_repeats_is_checked_with_a_later_version_to_upgrade_to(self):
        code, out, checks = self.run_pack()
        self.assertEqual(code, 0, out)
        self.assertIn("pacman/verify-pacman.sh", checks)
        self.assertIn("epistle-1.2.3-1-x86_64.pkg.tar.zst", checks)
        self.assertIn("epistle-1.2.4-1-x86_64.pkg.tar.zst", checks)

    def test_two_builds_that_differ_stop_before_the_package_is_checked(self):
        code, out, checks = self.run_pack(DIFFERS="1")
        self.assertEqual(code, 1, out)
        self.assertIn("two builds of the same payload differ", out)
        self.assertNotIn("pacman/verify-pacman.sh", checks)


class TheDayOfTheArchImage(unittest.TestCase):
    """build-pacman.sh with a stand-in engine: the snapshot comes from the label of the image, or nothing is built."""

    def run_build(self, label):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            stage = tmp / "stage"
            (stage / "root/usr/bin").mkdir(parents=True)
            (stage / "root/usr/bin/epistle").write_bytes(b"\x7fELF" + b"\x00" * 14 + b"\x3e\x00")
            (stage / "files.txt").write_text("")
            (stage / "epoch").write_text("1\n")
            engine = tmp / "engine"
            engine.write_text(
                '#!/usr/bin/env bash\n'
                'echo "$*" >>"$CALLS"\n'
                'case "$*" in\n'
                '  *--format*) echo "$LABEL" ;;\n'
                '  "image inspect "*) exit 1 ;;\n'
                '  run*) touch "$OUT/epistle-1.2.3-1-x86_64.pkg.tar.zst" ;;\n'
                'esac\n'
            )
            engine.chmod(0o755)
            done = subprocess.run(
                ["bash", str(HERE / "build-pacman.sh"), str(stage), str(tmp / "out"), "1.2.3"],
                capture_output=True, text=True, check=False,
                env={**os.environ, "CONTAINER_ENGINE": str(engine), "LABEL": label,
                     "CALLS": str(tmp / "calls"), "OUT": str(tmp / "out")},
            )
            return done.returncode, done.stdout + done.stderr, (tmp / "calls").read_text()

    def test_the_snapshot_is_the_day_of_the_version_label_and_the_image_is_asked_for_by_digest(self):
        code, out, calls = self.run_build("20260102.0.123456")
        self.assertEqual(code, 0, out)
        self.assertIn("--build-arg SNAPSHOT=2026/01/02 ", calls)
        inspected = next(line for line in calls.splitlines() if "--format" in line)
        self.assertRegex(inspected, r" docker\.io/library/archlinux@sha256:[0-9a-f]{64}$")

    def test_a_label_that_names_no_day_builds_nothing(self):
        for label in ("", "latest", "2026012.0.1", "20260102", "20260102.0.1;x"):
            code, out, calls = self.run_build(label)
            self.assertEqual(code, 1, (label, out))
            self.assertIn("names no day", out)
            self.assertNotIn("build --quiet", calls)


if __name__ == "__main__":
    unittest.main()
