"""The exact set of release files, checked on real directories and real packages."""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "release_files.py"
TAG = "v1.2.3"
VERSION = "1.2.3"


def deb(path, package="epistle", version=VERSION, arch="amd64", payload=None):
    """A real, empty package with the given control fields."""
    with tempfile.TemporaryDirectory() as tree:
        control = Path(tree) / "DEBIAN"
        control.mkdir()
        (control / "control").write_text(
            f"Package: {package}\nVersion: {version}\nArchitecture: {arch}\nMaintainer: t <t@example.org>\n"
            "Description: fixture\n"
        )
        if payload:
            (Path(tree) / "payload").write_bytes(payload)
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", tree, str(path)], check=True, capture_output=True)


def run(*args):
    done = subprocess.run(["python3", "-I", str(SCRIPT), *args], capture_output=True, text=True, check=False)
    return done.returncode, done.stdout + done.stderr


def write_sums(dist):
    lines = []
    for path in sorted(Path(dist).iterdir()):
        if path.is_file() and not path.is_symlink() and path.name != "SHA256SUMS" and not path.name.endswith(".sig"):
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (Path(dist) / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def make_dist(dist):
    """The directory a build hands over: the binary, the SBOM, one real package for each architecture and the sums."""
    dist = Path(dist)
    dist.mkdir(parents=True, exist_ok=True)
    (dist / f"epistle-{TAG}-x86_64-linux").write_bytes(b"binary")
    (dist / f"epistle-{TAG}.cdx.json").write_text("{}")
    deb(dist / f"epistle_{VERSION}_amd64.deb", arch="amd64")
    deb(dist / f"epistle_{VERSION}_arm64.deb", arch="arm64")
    for arch in ("x86_64", "aarch64"):
        (dist / f"epistle-{VERSION}-1.glyndor.any.{arch}.rpm").write_bytes(f"rpm {arch}".encode())
    write_sums(dist)


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb is not installed")
class Directory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dist = Path(self.tmp.name) / "dist"
        make_dist(self.dist)

    def sums(self):
        write_sums(self.dist)

    def sign(self):
        for path in list(self.dist.iterdir()):
            if not path.name.endswith(".sig"):
                (self.dist / f"{path.name}.sig").write_bytes(b"signature")

    def check(self, stage="built", tag=TAG):
        return run("check", str(self.dist), tag, stage)

    def test_the_exact_set_passes(self):
        code, out = self.check()
        self.assertEqual(code, 0, out)

    def test_the_exact_signed_set_passes_and_the_built_set_does_not_pass_as_signed(self):
        self.sign()
        self.assertEqual(self.check("signed")[0], 0)
        self.assertEqual(self.check("built")[0], 1)

    def test_an_extra_package_of_another_version_or_architecture_is_refused(self):
        for name in ("epistle_999.0.0_amd64.deb", f"epistle_{VERSION}_s390x.deb", f"epistle_{VERSION}_i386.deb"):
            with self.subTest(name=name):
                deb(self.dist / name)
                code, out = self.check()
                self.assertEqual(code, 1)
                self.assertIn(f"unexpected entry: {name}", out)
                (self.dist / name).unlink()

    def test_a_hidden_file_a_directory_and_a_nested_file_are_refused(self):
        (self.dist / ".hidden").write_text("x")
        (self.dist / "sub").mkdir()
        (self.dist / "sub" / "inner").write_text("x")
        code, out = self.check()
        self.assertEqual(code, 1)
        for name in (".hidden", "sub", "sub/inner"):
            self.assertIn(f"unexpected entry: {name}", out)

    def test_a_link_in_place_of_a_file_is_refused(self):
        target = Path(self.tmp.name) / "elsewhere"
        target.write_text("x")
        (self.dist / f"epistle-{TAG}.cdx.json").unlink()
        os.symlink(target, self.dist / f"epistle-{TAG}.cdx.json")
        code, out = self.check()
        self.assertEqual(code, 1)
        self.assertIn("is not a regular file", out)

    def test_a_missing_file_is_named(self):
        (self.dist / "SHA256SUMS").unlink()
        code, out = self.check()
        self.assertEqual(code, 1)
        self.assertIn("missing: SHA256SUMS", out)

    def test_the_control_fields_of_each_package_are_read(self):
        deb(self.dist / f"epistle_{VERSION}_amd64.deb", package="other")
        self.sums()
        self.assertIn("Package is 'other'", self.check()[1])
        deb(self.dist / f"epistle_{VERSION}_amd64.deb", version="9.9.9")
        self.sums()
        self.assertIn("Version is '9.9.9'", self.check()[1])
        deb(self.dist / f"epistle_{VERSION}_amd64.deb", arch="arm64")
        self.sums()
        self.assertIn("Architecture is 'arm64'", self.check()[1])

    def test_a_file_that_is_not_the_one_the_sums_describe_is_refused(self):
        (self.dist / f"epistle-{TAG}.cdx.json").write_text('{"changed": true}')
        code, out = self.check()
        self.assertEqual(code, 1)
        self.assertIn("does not match its hash", out)

    def test_sums_that_name_something_else_are_refused(self):
        (self.dist / "SHA256SUMS").write_text("0" * 64 + "  elsewhere\n")
        self.assertIn("does not name exactly the built files", self.check()[1])

    def test_an_empty_signature_is_refused(self):
        self.sign()
        (self.dist / "SHA256SUMS.sig").write_bytes(b"")
        self.assertIn("SHA256SUMS.sig is empty", self.check("signed")[1])

    def test_a_tag_that_is_not_a_release_shape_is_refused(self):
        for tag in ("1.2.3", "v1.2", "v01.2.3", "v1.2.3;rm", "v1.2.3 ", "main", ""):
            with self.subTest(tag=tag):
                code, out = self.check(tag=tag)
                self.assertEqual(code, 1)
                self.assertIn("error:", out)

    def test_the_names_are_derived_from_the_tag(self):
        code, out = run("names", "v0.13.4", "built")
        self.assertEqual(code, 0)
        self.assertEqual(out.split(), ["SHA256SUMS", "epistle-0.13.4-1.glyndor.any.aarch64.rpm", "epistle-0.13.4-1.glyndor.any.x86_64.rpm",
                                       "epistle-v0.13.4-x86_64-linux", "epistle-v0.13.4.cdx.json",
                                       "epistle_0.13.4_amd64.deb", "epistle_0.13.4_arm64.deb"])
        self.assertEqual(len(run("names", "v0.13.4", "signed")[1].split()), 14)

    def test_a_prerelease_tag_names_its_packages_with_the_prerelease(self):
        self.assertIn("epistle_1.0.0-rc.1_amd64.deb", run("names", "v1.0.0-rc.1", "built")[1])


if __name__ == "__main__":
    unittest.main()
