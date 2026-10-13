#!/usr/bin/env python3
"""Pins the `gh issue list` shape of `lookup_existing` in
`.github/scripts/rust_audit_combine.py`.

The brief is explicit: the broken `tr ',' '%2C'` substitution must not
return, in either the workflow or this script. This test imports the
script directly and replaces `subprocess.run` with a recording fake,
then asserts the command built for the lookup uses `gh issue list` with
a `--label` flag for each of the four labels, and `gh api` is nowhere
in the command.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
COMBINE_PY = REPO_ROOT / ".github" / "scripts" / "rust_audit_combine.py"


def _load_combine():
	"""Import `rust_audit_combine.py` from its absolute path."""
	spec = importlib.util.spec_from_file_location("rust_audit_combine", COMBINE_PY)
	assert spec is not None and spec.loader is not None
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


class _RecordingRun:
	"""Substitute for `subprocess.run` that records the argv it was
	called with and returns a canned result. The combine script calls
	`subprocess.run(cmd, capture_output=True, text=True, check=False)`
	once per `lookup_existing`; we only need the argv."""

	def __init__(self, payload):
		self.payload = payload
		self.calls = []

	def __call__(self, cmd, *, input, capture_output, text, check, env=None):  # noqa: A002
		self.calls.append(list(cmd))
		return subprocess.CompletedProcess(
			cmd, 0, stdout=json.dumps(self.payload), stderr=""
		)


class TestLookupExisting(unittest.TestCase):
	"""The lookup must call `gh issue list --label ...`, never `gh api`."""

	def test_lookup_uses_gh_issue_list_with_repeated_label_flags(self) -> None:
		combine = _load_combine()
		recorder = _RecordingRun(payload=[])
		original = combine.subprocess.run
		combine.subprocess.run = recorder
		try:
			combine.lookup_existing("owner/name", "Dependency advisories: A")
		finally:
			combine.subprocess.run = original
		combine = _load_combine()
		recorder = _RecordingRun(payload=[])
		original = combine.subprocess.run
		combine.subprocess.run = recorder
		try:
			combine.lookup_existing("owner/name", "Dependency advisories: A")
		finally:
			combine.subprocess.run = original

		self.assertEqual(len(recorder.calls), 1, msg=recorder.calls)
		cmd = recorder.calls[0]

		self.assertEqual(
			cmd[:3],
			["gh", "issue", "list"],
			msg=f"lookup must start with `gh issue list`, got: {cmd}",
		)

		# No `gh api` anywhere in the command.
		for token in cmd:
			self.assertNotEqual(
				token,
				"api",
				msg=f"lookup uses `gh api` instead of `gh issue list`: {cmd}",
			)

		# Each of the four labels must appear as a separate `--label <value>` pair.
		expected = ["type:security", "type:deps", "prio:P1", "area:meta"]
		got = []
		for i, token in enumerate(cmd[:-1]):
			if token == "--label":
				got.append(cmd[i + 1])
		self.assertEqual(
			got,
			expected,
			msg=f"expected one `--label` flag per audit label; got {got}",
		)

	def test_lookup_filters_by_exact_title_not_substring(self) -> None:
		# An issue titled with a wider set must not be returned as the
		# match for a narrower set; the combine script filters the JSON
		# output by exact title in Python.
		combine = _load_combine()
		issues = [
			{"number": 7, "title": "Dependency advisories: A, B"},
			{"number": 8, "title": "Dependency advisories: A"},
			{"number": 9, "title": "Dependency advisories: A, C"},
		]
		recorder = _RecordingRun(payload=issues)
		original = combine.subprocess.run
		combine.subprocess.run = recorder
		try:
			matched = combine.lookup_existing("owner/name", "Dependency advisories: A")
		finally:
			combine.subprocess.run = original

		self.assertEqual(
			matched,
			"8",
			msg=f"expected exact title match to return issue 8, got {matched!r}",
		)

	def test_lookup_returns_empty_string_when_no_match(self) -> None:
		combine = _load_combine()
		issues = [{"number": 11, "title": "Something else entirely"}]
		recorder = _RecordingRun(payload=issues)
		original = combine.subprocess.run
		combine.subprocess.run = recorder
		try:
			matched = combine.lookup_existing("owner/name", "Dependency advisories: A")
		finally:
			combine.subprocess.run = original

		self.assertEqual(
			matched,
			"",
			msg=f"expected empty string when no exact match, got {matched!r}",
		)

	def test_lookup_returns_empty_string_on_gh_failure(self) -> None:
		# `gh` exits non-zero on auth failure or network error; the
		# workflow needs to open a new issue in that case, so the
		# lookup must surface empty rather than raise.
		combine = _load_combine()

		def _failing_run(cmd, *, input=None, capture_output=None, text=None, check=None, env=None):
			import subprocess as _subprocess

			return _subprocess.CompletedProcess(cmd, 1, stdout="", stderr="auth required")

		original = combine.subprocess.run
		combine.subprocess.run = _failing_run
		try:
			matched = combine.lookup_existing("owner/name", "Dependency advisories: A")
		finally:
			combine.subprocess.run = original

		self.assertEqual(matched, "")


if __name__ == "__main__":
	unittest.main()
