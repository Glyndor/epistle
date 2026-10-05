#!/usr/bin/env python3
"""Tests for `.github/scripts/image_tags.py`.

Run from the repository root with:

	python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v

Drives the script as an external command, the way `release.yml` drives it,
so a regression in argv parsing, in the `::error::` annotation, or in
exit codes surfaces as a failing test, not a half-built manifest list on
ghcr.io.

A prerelease must never produce a floating tag, because `:0` would then
move onto a release candidate and a consumer pinning the major would
pull the candidate as if it were the next stable. A plain version must
produce all three, in the order the manifest list is built. Anything
else must fail, because what `podman manifest create` would then do is
undefined and the failure shows up as a half-built list on ghcr.io.
"""

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TAGS_PY = REPO_ROOT / ".github" / "scripts" / "image_tags.py"


def _classify(raw: str) -> subprocess.CompletedProcess:
	"""Invoke `image_tags.py` with `raw` as its only argument.

	The script reads no environment, so the inherited one is fine. The
	capture is on stdout and stderr together, because the assertion is
	on the exit code and the printed tags; a tag printed on stderr is
	not a tag the workflow would see.
	"""
	return subprocess.run(
		[sys.executable, str(TAGS_PY), raw],
		capture_output=True,
		cwd=str(REPO_ROOT),
		text=True,
		check=False,
	)


def _expect_tags(test: unittest.TestCase, raw: str, want: list[str]) -> None:
	"""Assert the script exits 0 and prints exactly `want`, one per line."""
	proc = _classify(raw)
	test.assertEqual(
		proc.returncode, 0,
		msg=f"classify({raw!r}) exited {proc.returncode}: {proc.stderr}",
	)
	got = proc.stdout.splitlines()
	test.assertEqual(
		got, want,
		msg=f"classify({raw!r}) printed {got!r}, want {want!r}",
	)


def _expect_error(
	test: unittest.TestCase, raw: str, needle: str
) -> None:
	"""Assert the script exits 1, emits `::error::`, and stderr contains `needle`.

	The `::error::` prefix is what GitHub Actions renders as a red
	annotation; without it the message is just free-form text, and a
	maintainer at 3 a.m. has to dig. The exit code is the gate the
	workflow relies on; stderr is the human-readable explanation.
	"""
	proc = _classify(raw)
	test.assertEqual(
		proc.returncode, 1,
		msg=f"classify({raw!r}) exited {proc.returncode}, want 1: "
		f"stdout={proc.stdout!r} stderr={proc.stderr!r}",
	)
	test.assertTrue(
		proc.stdout == "" or proc.stdout.splitlines() == [],
		msg=f"a rejected version printed tags to stdout: {proc.stdout!r}",
	)
	test.assertIn("::error::", proc.stderr)
	test.assertIn(
		needle, proc.stderr,
		msg=f"classify({raw!r}) stderr {proc.stderr!r} does not contain {needle!r}",
	)


class TestPlainVersion(unittest.TestCase):
	"""A plain version publishes the exact, the minor, and the major tags.

	Order matters: the exact tag is the first one the manifest list is
	built for, and the floating tags re-point at the same list. Reversing
	the order would still produce a working list, but the digestfile the
	job reads would be the floating one, not the exact one, and a future
	edit that relies on `digest-<exact>` would break.
	"""

	def test_v0_9_0_publishes_three_tags(self) -> None:
		_expect_tags(self, "v0.9.0", ["0.9.0", "0.9", "0"])

	def test_v0_10_3_publishes_three_tags(self) -> None:
		# The minor and major are the same width as `0.9`, so the
		# output looks the same. The case exists to prove the script
		# does not key on string length when it splits on `.`.
		_expect_tags(self, "v0.10.3", ["0.10.3", "0.10", "0"])

	def test_bare_version_without_v_publishes_three_tags(self) -> None:
		# `cargo metadata` reports `0.9.0`; the git tag is `v0.9.0`.
		# The release job normalises the input, but the script is the
		# gate, so a future caller that does not normalise should
		# still get the right answer.
		_expect_tags(self, "0.9.0", ["0.9.0", "0.9", "0"])


class TestPrerelease(unittest.TestCase):
	"""A prerelease publishes the exact tag only — the whole point of the change.

	`v1.0.0-rc.1` previously produced `1.0.0-rc`, `1.0`, and `1`, and
	`:1` would land on a candidate. A prerelease must publish the exact
	tag so a consumer that wants the candidate pulls it by name, while
	the floating tags wait for the stable cut.
	"""

	def test_v1_0_0_rc_1_publishes_only_the_exact_tag(self) -> None:
		_expect_tags(self, "v1.0.0-rc.1", ["1.0.0-rc.1"])


class TestRefused(unittest.TestCase):
	"""Anything that is not `MAJOR.MINOR.PATCH[-prerelease]` is refused.

	The script must refuse to publish at all on a tag it cannot
	classify. What `podman manifest create` would then do is undefined,
	and a half-built manifest list on ghcr.io is worse than a missing
	release. Each case below names the specific failure mode the
	script has to catch.
	"""

	def test_leading_zero_on_minor_is_refused(self) -> None:
		_expect_error(self, "v0.09.0", "leading zero")

	def test_two_dashes_in_a_row_are_refused(self) -> None:
		_expect_error(self, "v0.9.0--rc", "not MAJOR.MINOR.PATCH")

	def test_non_alphanumeric_patch_is_refused(self) -> None:
		_expect_error(self, "v0.9.x", "not MAJOR.MINOR.PATCH")

	def test_empty_string_is_refused(self) -> None:
		_expect_error(self, "", "not MAJOR.MINOR.PATCH")

	def test_garbage_is_refused(self) -> None:
		_expect_error(self, "garbage", "not MAJOR.MINOR.PATCH")


if __name__ == "__main__":
	unittest.main()
