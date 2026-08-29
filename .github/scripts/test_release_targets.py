"""The release workflow must install the target `debian/rules` builds for.

`debian/rules` cross-compiles the .deb to musl so the package stops carrying a
glibc floor. The release container ships only its own target's standard
library, so the release job has to `rustup target add` the matching triple; if
it does not, the build dies on "can't find crate for `core`" after downloading
the whole dependency tree.

That divergence is not hypothetical. It shipped: `debian/rules` moved to musl
and `release.yml` was not updated, so releasing was impossible from that merge
until someone actually tried to cut one. The PR-time .deb job passes throughout,
because it installs the target through a different workflow.

This asserts the two files agree, per architecture.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
RULES = ROOT / "debian" / "rules"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"


def targets_in_rules() -> dict[str, str]:
    """`RUST_TARGET_<arch> = <triple>` lines from debian/rules."""
    return {
        arch: triple
        for arch, triple in re.findall(
            r"^RUST_TARGET_(\w+)\s*=\s*(\S+)\s*$", RULES.read_text(), re.MULTILINE
        )
    }


def targets_in_release() -> dict[str, str]:
    """`<arch>) target=<triple> ;;` arms from the release workflow."""
    return {
        arch: triple
        for arch, triple in re.findall(
            r"^\s*(\w+)\)\s*target=(\S+)\s*;;", RELEASE.read_text(), re.MULTILINE
        )
    }


class ReleaseTargetsMatchDebianRules(unittest.TestCase):
    def test_the_patterns_still_find_something(self) -> None:
        # A regex that silently matches nothing would make every assertion
        # below pass on an empty set. Check the ground before reading it.
        self.assertTrue(targets_in_rules(), "no RUST_TARGET_<arch> in debian/rules")
        self.assertTrue(targets_in_release(), "no target= arm in release.yml")

    def test_every_architecture_debian_builds_is_installed_by_the_release(self) -> None:
        rules, release = targets_in_rules(), targets_in_release()
        for arch, triple in rules.items():
            self.assertIn(
                arch,
                release,
                f"debian/rules builds {arch} but release.yml installs no target for it",
            )
            self.assertEqual(
                release[arch],
                triple,
                f"{arch}: debian/rules builds {triple}, release.yml installs {release[arch]}",
            )

    def test_the_release_installs_no_architecture_debian_does_not_build(self) -> None:
        rules, release = targets_in_rules(), targets_in_release()
        for arch in release:
            self.assertIn(
                arch, rules, f"release.yml maps {arch}, debian/rules does not build it"
            )


if __name__ == "__main__":
    unittest.main()
