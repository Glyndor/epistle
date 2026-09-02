#!/usr/bin/env python3
"""Tests for `.github/scripts/dependabot_security_watch.py`.

Run from the repository root with:

	python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v

Drives the script as an external command over fixed JSON, the way the
workflow drives it, with `--now` pinned so ages are deterministic. Every
assertion is on an exit code or on a pull request number appearing in the
output; none is on a sentence, so rewording the report cannot break a test.

Both directions are covered on purpose: silent when nothing is stuck, loud
the moment one is. A watcher that only has the loud case tested is one edit
away from suppressing everything.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WATCH_PY = REPO_ROOT / ".github" / "scripts" / "dependabot_security_watch.py"
NOW = "2026-09-02T12:00:00Z"


def _pr(number: int, login: str, head: str, *, author_shape: str = "object") -> dict:
	"""One listing entry, with the author in the user or the app shape."""
	author = {"login": login, "is_bot": login != "jaro-c"} if author_shape == "object" else login
	return {
		"number": number,
		"title": f"bump something for #{number}",
		"author": author,
		"headRefName": head,
		"createdAt": "2026-08-20T09:00:00Z",
	}


def _run(payload: str, *args: str) -> subprocess.CompletedProcess:
	"""Invoke the script with `payload` on stdin and a pinned clock."""
	return subprocess.run(
		[sys.executable, str(WATCH_PY), "--now", NOW, *args],
		input=payload,
		capture_output=True,
		cwd=str(REPO_ROOT),
		text=True,
		check=False,
	)


def _run_json(pull_requests: list) -> subprocess.CompletedProcess:
	return _run(json.dumps(pull_requests))


class TestNothingStuck(unittest.TestCase):
	"""The silent direction: exit 0 and no pull request number named."""

	def test_empty_list_exits_zero(self) -> None:
		proc = _run_json([])
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)

	def test_human_pull_request_into_main_is_not_stuck(self) -> None:
		proc = _run_json([_pr(101, "jaro-c", "release/0.5.0")])
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		self.assertNotIn("#101", proc.stdout)

	def test_dependabot_from_develop_is_a_release_not_stuck(self) -> None:
		# A Dependabot-authored pull request whose head is develop is the
		# normal release path, which main-guard admits. Reporting it would
		# be the false positive that teaches people to ignore the check.
		proc = _run_json([_pr(102, "app/dependabot", "develop")])
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		self.assertNotIn("#102", proc.stdout)


class TestStuck(unittest.TestCase):
	"""The loud direction: exit 1 and every stuck number in the output."""

	def test_dependabot_branch_into_main_exits_one_and_names_the_number(self) -> None:
		proc = _run_json([_pr(103, "app/dependabot", "dependabot/pip/main/.github/scripts/cryptography-50.0.1")])
		self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
		self.assertIn("#103", proc.stdout)

	def test_two_stuck_are_both_named(self) -> None:
		proc = _run_json([
			_pr(104, "app/dependabot", "dependabot/pip/main/.github/scripts/cryptography-50.0.1"),
			_pr(105, "jaro-c", "develop"),
			_pr(106, "app/dependabot", "dependabot/cargo/main/rustls-0.23.99"),
		])
		self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
		self.assertIn("#104", proc.stdout)
		self.assertIn("#106", proc.stdout)
		self.assertNotIn("#105", proc.stdout)

	def test_author_as_user_login_object(self) -> None:
		proc = _run_json([_pr(107, "dependabot[bot]", "dependabot/cargo/main/x-1.0.0")])
		self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
		self.assertIn("#107", proc.stdout)

	def test_author_as_bare_string_in_both_spellings(self) -> None:
		# Older gh printed `author` as a plain login string. Both spellings
		# in that shape have to count, or a gh upgrade or downgrade turns the
		# watcher silent without anything going red.
		for login in ("dependabot[bot]", "app/dependabot"):
			with self.subTest(login=login):
				proc = _run_json([_pr(108, login, "dependabot/cargo/main/x-1.0.0", author_shape="string")])
				self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
				self.assertIn("#108", proc.stdout)

	def test_file_argument_reads_the_same_listing(self) -> None:
		with tempfile.TemporaryDirectory() as tmpdir:
			listing = Path(tmpdir) / "prs.json"
			listing.write_text(json.dumps([_pr(109, "app/dependabot", "dependabot/pip/main/y-2.0.0")]))
			proc = _run("", str(listing))
		self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
		self.assertIn("#109", proc.stdout)

	def test_unreadable_created_at_still_reports_the_number(self) -> None:
		entry = _pr(110, "app/dependabot", "dependabot/pip/main/z-3.0.0")
		entry["createdAt"] = "not a date"
		proc = _run_json([entry])
		self.assertEqual(proc.returncode, 1, msg=proc.stdout + proc.stderr)
		self.assertIn("#110", proc.stdout)


class TestUnreadableInput(unittest.TestCase):
	"""A watcher that cannot read its input fails; it never reports clean."""

	def test_malformed_json_exits_two(self) -> None:
		proc = _run("{not json")
		self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)

	def test_json_object_instead_of_list_exits_two(self) -> None:
		proc = _run(json.dumps({"number": 1}))
		self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)

	def test_entry_without_number_exits_two(self) -> None:
		proc = _run(json.dumps([{"author": {"login": "app/dependabot"}, "headRefName": "x"}]))
		self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)

	def test_missing_file_exits_two(self) -> None:
		proc = _run("", os.path.join(tempfile.gettempdir(), "does-not-exist-676.json"))
		self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)

	def test_bad_now_exits_two(self) -> None:
		proc = subprocess.run(
			[sys.executable, str(WATCH_PY), "--now", "yesterday"],
			input="[]",
			capture_output=True,
			cwd=str(REPO_ROOT),
			text=True,
			check=False,
		)
		self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)


if __name__ == "__main__":
	unittest.main()
