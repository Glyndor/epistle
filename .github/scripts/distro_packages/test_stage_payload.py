"""The staging of the .deb payload: what it carries over, what it changes and what it refuses.

The packages here are made by the test, byte by byte, so that a hostile one can be
made too. The postinst is the one of this repository, so a change to it that the
staging cannot carry over fails here and not at release time.
"""

import hashlib
import io
import lzma
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path

from distro_packages import stage_payload as sp

ROOT = Path(__file__).resolve().parents[3]
VERSION = "1.2.3"
EPOCH = 1_700_000_000
POSTINST = (ROOT / "debian/epistle.postinst").read_bytes()


def elf(machine=62, interpreter=False):
    """A 64-bit little-endian ELF header with one program header."""
    header = bytearray(64 + 56)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = machine.to_bytes(2, "little")
    header[32:40] = (64).to_bytes(8, "little")
    header[54:56] = (56).to_bytes(2, "little")
    header[56:58] = (1).to_bytes(2, "little")
    header[64:68] = (3 if interpreter else 1).to_bytes(4, "little")
    return bytes(header)


def payload(machine=62):
    files = {name: f"content of {name}\n".encode() for name in sp.FIXED}
    files[sp.BINARY] = elf(machine)
    for name in (
        "usr/share/man/man1/epistle.1.gz",
        "usr/share/man/man1/epistle-account-add.1.gz",
        "usr/share/doc/epistle/README.md.gz",
        "usr/share/doc/epistle/epistle.service",
    ):
        files[name] = f"content of {name}\n".encode()
    return files


def tar_xz(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:") as tar:
        for name, blob, kind in members:
            info = tarfile.TarInfo(name)
            info.mtime = EPOCH
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(blob)
                tar.addfile(info, io.BytesIO(blob))
            else:
                info.linkname = blob.decode()
                tar.addfile(info)
    return lzma.compress(buffer.getvalue())


def ar(members):
    out = b"!<arch>\n"
    for name, blob in members:
        out += f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(blob):<10}`\n".encode() + blob
        out += b"\n" * (len(blob) & 1)
    return out


def deb(path, files=None, version=VERSION, arch="amd64", package="epistle", postinst=POSTINST, extra=()):
    files = payload() if files is None else files
    control = f"Package: {package}\nVersion: {version}\nArchitecture: {arch}\n".encode()
    meta = [("./control", control, tarfile.REGTYPE)]
    if postinst is not None:
        meta.append(("./postinst", postinst, tarfile.REGTYPE))
    data = [(f"./{name}", blob, tarfile.REGTYPE) for name, blob in files.items()] + list(extra)
    Path(path).write_bytes(
        ar([("debian-binary", b"2.0\n"), ("control.tar.xz", tar_xz(meta)), ("data.tar.xz", tar_xz(data))])
    )


class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.deb = self.tmp / "epistle.deb"
        self.out = self.tmp / "stage"

    def stage(self, arch="amd64", version=VERSION, repository=ROOT):
        return sp.stage(str(self.deb), version, arch, str(repository), str(self.out))

    def refused(self, fragment, **kwargs):
        with self.assertRaises(sp.Refused) as caught:
            self.stage(**kwargs)
        self.assertIn(fragment, str(caught.exception))
        self.assertFalse(self.out.exists(), "a refused package leaves nothing behind")

    def listing(self):
        rows = [line.split(" ") for line in (self.out / "files.txt").read_text().splitlines()]
        return {path: (mode, sha, int(size)) for mode, path, sha, size in rows}


class Carried(Case):
    def test_the_tree_is_the_debs_with_exactly_these_moves_and_additions(self):
        files = payload()
        deb(self.deb, files)
        self.stage()
        moved = {
            "usr/lib/sysctl.d/30-glyndor-epistle.conf": "usr/lib/epistle/sysctl.d/30-glyndor-epistle.conf",
            "usr/share/zsh/vendor-completions/_epistle": "usr/share/zsh/site-functions/_epistle",
            "usr/share/doc/epistle/copyright": "usr/share/licenses/epistle/copyright",
        }
        added = {
            "usr/lib/epistle/configure",
            "usr/lib/epistle/setup",
            "usr/lib/sysusers.d/epistle.conf",
            "usr/share/licenses/epistle/LICENSE",
        }
        listing = self.listing()
        self.assertEqual(set(listing), {moved.get(name, name) for name in files} | added)
        for name, blob in files.items():
            mode, sha, size = listing[moved.get(name, name)]
            self.assertEqual((sha, size), (hashlib.sha256(blob).hexdigest(), len(blob)), name)
            self.assertEqual(mode, "0755" if name == sp.BINARY else "0644", name)

    def test_the_files_on_disk_have_the_listed_modes_and_the_time_of_the_binary(self):
        deb(self.deb)
        self.stage()
        for path, (mode, _sha, _size) in self.listing().items():
            found = os.stat(self.out / "root" / path)
            self.assertEqual(stat.S_IMODE(found.st_mode), int(mode, 8), path)
            self.assertEqual(int(found.st_mtime), EPOCH, path)
        self.assertEqual((self.out / "epoch").read_text(), f"{EPOCH}\n")
        for path in (self.out / "root").rglob("*"):
            if path.is_dir():
                self.assertEqual((stat.S_IMODE(path.stat().st_mode), int(path.stat().st_mtime)), (0o755, EPOCH), path)

    def test_the_package_owns_only_the_directories_that_are_its_own(self):
        deb(self.deb)
        self.stage()
        self.assertEqual(
            (self.out / "dirs.txt").read_text().splitlines(),
            ["usr/lib/epistle", "usr/lib/epistle/sysctl.d", "usr/share/doc/epistle", "usr/share/licenses/epistle"],
        )

    def test_nothing_is_installed_where_a_channel_refuses_it(self):
        deb(self.deb)
        self.stage()
        for path in self.listing():
            self.assertFalse(path.startswith(("etc/", "var/", "usr/lib/sysctl.d/", "usr/share/zsh/vendor-completions/")), path)

    def test_setup_the_account_and_the_licence_are_the_repositorys(self):
        deb(self.deb)
        self.stage()
        root = self.out / "root"
        for source, target in (
            ("packaging/linux/setup.sh", "usr/lib/epistle/setup"),
            ("packaging/linux/sysusers.conf", "usr/lib/sysusers.d/epistle.conf"),
            ("LICENSE", "usr/share/licenses/epistle/LICENSE"),
        ):
            self.assertEqual((root / target).read_bytes(), (ROOT / source).read_bytes(), target)

    def test_configure_is_the_postinst_with_the_two_debian_things_rewritten(self):
        deb(self.deb)
        self.stage()
        got = (self.out / "root/usr/lib/epistle/configure").read_text()
        original = POSTINST.decode()
        self.assertNotIn("dpkg", got)
        self.assertNotIn("/usr/lib/sysctl.d/30-glyndor-epistle.conf", got)
        undone = got.replace("sudo /usr/lib/epistle/setup", "@AGAIN@").replace(
            "/usr/lib/epistle/sysctl.d/", "/usr/lib/sysctl.d/"
        )
        expected = sp.RECONFIGURE_RE.sub("@AGAIN@", original)
        self.assertEqual(undone, expected)

    def test_a_document_may_arrive_compressed_or_not(self):
        files = payload()
        files["usr/share/doc/epistle/epistle.service.gz"] = files.pop("usr/share/doc/epistle/epistle.service")
        files["usr/share/doc/epistle/README.md"] = files.pop("usr/share/doc/epistle/README.md.gz")
        deb(self.deb, files)
        self.stage()
        self.assertIn("usr/share/doc/epistle/epistle.service.gz", self.listing())

    def test_an_arm64_binary_stages_for_arm64(self):
        deb(self.deb, payload(183), arch="arm64")
        self.stage(arch="arm64")
        self.assertIn("usr/bin/epistle", self.listing())


class Refusals(Case):
    def test_another_package_version_or_architecture(self):
        for field, kwargs in (("Package", {"package": "other"}), ("Version", {"version": "9.9.9"}),
                              ("Architecture", {"arch": "arm64"})):
            deb(self.deb, **kwargs)
            self.refused(f"control says {field}")

    def test_a_version_that_is_not_three_numbers(self):
        deb(self.deb)
        for version in ("1.2", "1.2.3-rc1", "v1.2.3", "1.2.3\n", "../1.2.3"):
            self.refused("is not X.Y.Z", version=version)

    def test_a_binary_of_another_architecture_or_a_dynamic_one(self):
        deb(self.deb, payload(183))
        self.refused("another architecture")
        files = payload()
        files[sp.BINARY] = elf(interpreter=True)
        deb(self.deb, files)
        self.refused("dynamic loader")
        files[sp.BINARY] = b"#!/bin/sh\n"
        deb(self.deb, files)
        self.refused("not an ELF")

    def test_a_file_nobody_declared(self):
        for name in ("etc/epistle/epistle.toml", "usr/lib/systemd/system/epistle.service",
                     "usr/share/man/man1/other.1.gz", "usr/share/doc/epistle/NEWS.gz", "usr/bin/other"):
            files = payload()
            files[name] = b"x"
            deb(self.deb, files)
            self.refused("does not know")

    def test_a_file_that_is_missing(self):
        for name in (*sp.FIXED, sp.REQUIRED_MAN):
            files = payload()
            del files[name]
            deb(self.deb, files)
            self.refused("the .deb lacks")

    def test_a_document_missing_or_carried_twice(self):
        files = payload()
        del files["usr/share/doc/epistle/epistle.service"]
        deb(self.deb, files)
        self.refused("once, compressed or not")
        files = payload()
        files["usr/share/doc/epistle/README.md"] = b"x"
        deb(self.deb, files)
        self.refused("once, compressed or not")

    def test_a_link_a_path_that_leaves_the_root_and_a_name_twice(self):
        deb(self.deb, extra=[("./usr/share/man/man1/epistle-x.1.gz", b"/etc/shadow", tarfile.SYMTYPE)])
        self.refused("not a regular file or directory")
        deb(self.deb, extra=[("./usr/../etc/passwd", b"x", tarfile.REGTYPE)])
        self.refused("unsafe path")
        deb(self.deb, extra=[("/etc/passwd", b"x", tarfile.REGTYPE)])
        self.refused("unsafe path")
        deb(self.deb, extra=[("usr/bin/epistle", elf(), tarfile.REGTYPE)])
        self.refused("appears twice")

    def test_a_postinst_it_cannot_carry_over(self):
        text = POSTINST.decode()
        cases = {
            "no single regular": None,
            "not a /bin/sh script": text.replace("#!/bin/sh", "#!/bin/bash", 1),
            "no longer names the file": text.replace("/usr/lib/sysctl.d/30-glyndor-epistle.conf", "/somewhere"),
            "no longer says how to run it again": text.replace("dpkg-reconfigure epistle", "run it again"),
            "mentions dpkg": text + "\ndpkg --configure -a\n",
        }
        for fragment, changed in cases.items():
            deb(self.deb, postinst=None if changed is None else changed.encode())
            self.refused(fragment)

    def test_what_is_not_a_deb(self):
        self.deb.write_bytes(b"not an archive")
        self.refused("not an ar archive")
        self.deb.write_bytes(ar([("debian-binary", b"2.0\n"), ("data.tar.xz", b"")]))
        self.refused("unexpected .deb members")
        self.deb.write_bytes(ar([("debian-binary", b"2.0\n"), ("control.tar.xz", b"x"), ("data.tar.xz", b"x")]))
        self.refused("is not xz")

    def test_a_link_in_place_of_the_deb(self):
        deb(self.tmp / "real.deb")
        os.symlink(self.tmp / "real.deb", self.deb)
        self.refused("not a regular file")

    def test_a_repository_without_the_files_it_adds(self):
        deb(self.deb)
        self.refused("LICENSE is not a regular file", repository=self.tmp)

    def test_an_output_that_exists_is_not_written_into(self):
        deb(self.deb)
        self.out.mkdir()
        with self.assertRaises(sp.Refused):
            self.stage()
        self.assertEqual(os.listdir(self.out), [])

    def test_the_command_line_exits_one_on_a_refusal_and_zero_on_a_package(self):
        deb(self.deb)
        args = ["--deb", str(self.deb), "--version", VERSION, "--arch", "amd64",
                "--repository", str(ROOT), "--out", str(self.out)]
        self.assertEqual(sp.main(args), 0)
        self.assertEqual(sp.main(args), 1)


if __name__ == "__main__":
    unittest.main()
