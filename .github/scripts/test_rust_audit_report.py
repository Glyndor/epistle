#!/usr/bin/env python3
"""Tests for `.github/scripts/rust_audit_report.py`.

Run from the repository root with:

	python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v

Drives the script as an external command over fixed JSON, the way the
workflow drives it. Every assertion is on a JSON value emitted by the
script; nothing depends on a sentence in the body, so a wording change
that keeps the fields intact cannot break a test.

The fixtures are trimmed versions of what `cargo audit --json` produces;
the real shape is `vulnerabilities.list[]` of objects carrying the
advisory metadata, the package the audit hit, and the patched range. The
test asserts the script's three observable outcomes: the clean shape, the
dirty shape (with a title and a body), and the failure path (bad JSON,
non-object input).
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT_PY = REPO_ROOT / ".github" / "scripts" / "rust_audit_report.py"


def _vulnerability(
	advisory_id: str,
	package: str,
	version: str,
	patched: list[str],
	*,
	title: str = "an issue",
) -> dict:
	"""One cargo-audit JSON entry, the way `cargo audit --json` prints it.

	The shape is the public `rustsec::Vulnerability` serialization: the
	advisory metadata sits on `.advisory`, the patched range on
	`.versions.patched`, the package on `.package`.
	"""
	return {
		"advisory": {
			"id": advisory_id,
			"title": title,
			"description": "details",
			"date": "2026-09-01",
		},
		"versions": {"patched": patched, "unaffected": []},
		"affected": None,
		"package": {"name": package, "version": version},
	}


def _report(findings: list[dict]) -> dict:
	"""Wrap `findings` into the top-level `cargo audit --json` document."""
	return {
		"database": {"advisory-count": 1300, "last_updated": "2026-09-30T00:00:00Z"},
		"lockfile": {"dependency-count": 397},
		"settings": {"ignore": []},
		"vulnerabilities": {"found": bool(findings), "count": len(findings), "list": findings},
		"warnings": {},
	}


def _run(payload: str, ref: str) -> subprocess.CompletedProcess:
	"""Invoke the script with `payload` written to a temp file and a ref."""
	with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
		tmp.write(payload)
		path = tmp.name
	try:
		return subprocess.run(
			[sys.executable, str(SCRIPT_PY), path, ref],
			capture_output=True,
			text=True,
			check=False,
			cwd=str(REPO_ROOT),
		)
	finally:
		os.unlink(path)


def _run_stdin(payload: str, ref: str) -> subprocess.CompletedProcess:
	"""Invoke the script reading from stdin (the dash argument)."""
	return subprocess.run(
		[sys.executable, str(SCRIPT_PY), "-", ref],
		input=payload,
		capture_output=True,
		text=True,
		check=False,
		cwd=str(REPO_ROOT),
	)


class TestClean(unittest.TestCase):
	"""`vulnerabilities.found == false` (and the list is empty) yields the clean shape."""

	def test_empty_vulnerabilities_exits_zero_and_is_clean(self) -> None:
		proc = _run(json.dumps(_report([])), "develop")
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		report = json.loads(proc.stdout)
		self.assertTrue(report["clean"])
		self.assertIsNone(report["title"])
		self.assertIsNone(report["body"])
		self.assertEqual(report["ref"], "develop")
		self.assertEqual(report["advisories"], [])

	def test_found_false_with_empty_list_is_clean(self) -> None:
		# `found: false` plus an empty list is what a passing audit prints.
		proc = _run(json.dumps({"vulnerabilities": {"found": False, "count": 0, "list": []}}), "main")
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		report = json.loads(proc.stdout)
		self.assertTrue(report["clean"])


class TestDirty(unittest.TestCase):
	"""A non-empty `vulnerabilities.list` yields a deterministic title and body."""

	def test_single_advisory_title_lists_its_id(self) -> None:
		findings = [_vulnerability("RUSTSEC-2026-0338", "quinn-proto", "0.11.18", [">=0.11.19"])]
		proc = _run(json.dumps(_report(findings)), "develop")
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		report = json.loads(proc.stdout)
		self.assertFalse(report["clean"])
		self.assertEqual(report["title"], "Dependency advisories: RUSTSEC-2026-0338")
		self.assertEqual(report["ref"], "develop")
		self.assertEqual(len(report["advisories"]), 1)
		self.assertEqual(report["advisories"][0]["id"], "RUSTSEC-2026-0338")
		self.assertEqual(report["advisories"][0]["package"], "quinn-proto")
		self.assertEqual(report["advisories"][0]["version"], "0.11.18")
		self.assertEqual(report["advisories"][0]["patched"], ">=0.11.19")
		self.assertEqual(report["advisories"][0]["refs"], ["develop"])

	def test_multiple_advisories_sort_ids_in_title(self) -> None:
		findings = [
			_vulnerability("RUSTSEC-2026-0343", "quinn-proto", "0.11.18", [">=0.11.19"]),
			_vulnerability("RUSTSEC-2026-0338", "quinn-proto", "0.11.18", [">=0.11.19"]),
			_vulnerability("RUSTSEC-2026-0340", "quinn-proto", "0.11.18", [">=0.11.19"]),
		]
		proc = _run(json.dumps(_report(findings)), "main")
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		report = json.loads(proc.stdout)
		# Sorted, joined with comma+space: deterministic across runs so the
		# workflow's open-or-comment decision stays a title match, not a
		# fuzzy search.
		self.assertEqual(
			report["title"],
			"Dependency advisories: RUSTSEC-2026-0338, RUSTSEC-2026-0340, RUSTSEC-2026-0343",
		)

	def test_body_lists_every_advisory_with_patched_and_ref(self) -> None:
		findings = [
			_vulnerability("RUSTSEC-2026-0338", "quinn-proto", "0.11.18", [">=0.11.19"]),
			_vulnerability("RUSTSEC-2026-0340", "quinn-proto", "0.11.18", [">=0.11.19"]),
		]
		proc = _run(json.dumps(_report(findings)), "main")
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		report = json.loads(proc.stdout)
		body = report["body"]
		self.assertIsNotNone(body)
		self.assertIn("`main`", body)
		self.assertIn("RUSTSEC-2026-0338", body)
		self.assertIn("RUSTSEC-2026-0340", body)
		self.assertIn("`>=0.11.19`", body)
		self.assertIn("quinn-proto", body)
		self.assertIn("0.11.18", body)

	def test_advisory_without_patched_version_still_admitted(self) -> None:
		# A finding with no patched range is rare but legal; the body must
		# still mention it instead of dropping it from the issue.
		findings = [_vulnerability("RUSTSEC-2026-9999", "ghost", "9.9.9", [])]
		proc = _run(json.dumps(_report(findings)), "develop")
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		report = json.loads(proc.stdout)
		self.assertEqual(report["advisories"][0]["patched"], "")
		self.assertIn("no fixed version recorded", report["body"])

	def test_two_advisories_with_the_same_id_are_merged_in_the_title(self) -> None:
		# cargo-audit emits one entry per (advisory, package, range); the
		# title is the dedup'd id list, so duplicates collapse.
		findings = [
			_vulnerability("RUSTSEC-2026-0338", "quinn-proto", "0.11.18", [">=0.11.19"]),
			_vulnerability("RUSTSEC-2026-0338", "quinn-proto", "0.11.17", [">=0.11.19"]),
		]
		proc = _run(json.dumps(_report(findings)), "develop")
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		report = json.loads(proc.stdout)
		self.assertEqual(report["title"], "Dependency advisories: RUSTSEC-2026-0338")
		self.assertEqual(len(report["advisories"]), 2)

	def test_yanked_warning_without_rustsec_id_still_appears_in_the_title(self) -> None:
		# A yanked crate has no RUSTSEC id. The script still opens an issue
		# for it; the synthetic id keeps the title deterministic.
		report = _report([])
		report["warnings"] = {
			"yanked": [
				{
					"kind": "yanked",
					"package": {"name": "stale", "version": "0.1.0"},
					"advisory": None,
					"versions": None,
					"affected": None,
				}
			]
		}
		proc = _run(json.dumps(report), "develop")
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		out = json.loads(proc.stdout)
		self.assertFalse(out["clean"])
		self.assertEqual(out["title"], "Dependency advisories: yanked:stale@0.1.0")
		self.assertEqual(out["advisories"][0]["kind"], "yanked")
		self.assertEqual(out["advisories"][0]["package"], "stale")
		self.assertIn("`yanked`", out["body"])

	def test_warning_with_a_rustsec_id_uses_that_id(self) -> None:
		# Unmaintained advisories do carry a RUSTSEC id. The id round-trips
		# into the title.
		report = _report([])
		report["warnings"] = {
			"unmaintained": [
				{
					"kind": "unmaintained",
					"package": {"name": "old", "version": "0.2.0"},
					"advisory": {"id": "RUSTSEC-2024-9999"},
					"versions": {"patched": [], "unaffected": []},
					"affected": None,
				}
			]
		}
		proc = _run(json.dumps(report), "develop")
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		out = json.loads(proc.stdout)
		self.assertEqual(out["title"], "Dependency advisories: RUSTSEC-2024-9999")
		self.assertEqual(out["advisories"][0]["kind"], "unmaintained")


class TestStdin(unittest.TestCase):
	"""`rust_audit_report.py - <ref>` reads JSON from stdin."""

	def test_stdin_parses_a_dirty_report(self) -> None:
		findings = [_vulnerability("RUSTSEC-2026-0340", "quinn-proto", "0.11.18", [">=0.11.19"])]
		proc = _run_stdin(json.dumps(_report(findings)), "develop")
		self.assertEqual(proc.returncode, 0, msg=proc.stderr)
		report = json.loads(proc.stdout)
		self.assertEqual(report["ref"], "develop")
		self.assertEqual(report["title"], "Dependency advisories: RUSTSEC-2026-0340")


class TestUnreadableInput(unittest.TestCase):
	"""A bad input must fail loud, never report clean."""

	def test_malformed_json_exits_two(self) -> None:
		proc = _run("{not json", "develop")
		self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)

	def test_json_array_at_top_level_exits_two(self) -> None:
		proc = _run(json.dumps([{"vulnerabilities": {"list": []}}]), "develop")
		self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)

	def test_missing_vulnerabilities_field_exits_two(self) -> None:
		proc = _run(json.dumps({"database": {}, "lockfile": {}, "settings": {}, "warnings": {}}), "develop")
		self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)

	def test_missing_input_file_exits_two(self) -> None:
		proc = subprocess.run(
			[sys.executable, str(SCRIPT_PY), os.path.join(tempfile.gettempdir(), "does-not-exist-audit.json"), "develop"],
			capture_output=True,
			text=True,
			check=False,
			cwd=str(REPO_ROOT),
		)
		self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)


if __name__ == "__main__":
	unittest.main()
