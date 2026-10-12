#!/usr/bin/env python3
"""Tests for `.github/scripts/rust_audit_combine.py`.

Run from the repository root with:

	python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v

The combine script reads raw `cargo audit --json` documents from a
directory of `audit-json-<ref>/audit.json` files (the way the workflow
downloads them) and emits one combined JSON object. Every assertion is
on a JSON value the script emits; nothing depends on a sentence in the
body, so wording changes that keep the fields intact cannot break a
test.

The `--no-lookup` flag covers everything except the `gh` call,
because the call needs a real GitHub token and real network access. The
lookup branch is exercised manually by the workflow, where the token is
available in the step's `env:` block; here, the test only needs to prove
the branch is wired up correctly.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
COMBINE_PY = REPO_ROOT / ".github" / "scripts" / "rust_audit_combine.py"


def _vulnerability(
	advisory_id: str,
	package: str,
	version: str,
	patched: list[str],
	*,
	title: str = "an issue",
) -> dict:
	"""One cargo-audit JSON entry, the way `cargo audit --json` prints it."""
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


def _audit(findings: list[dict], warnings: dict | None = None) -> dict:
	"""Wrap `findings` into the top-level `cargo audit --json` document."""
	return {
		"database": {"advisory-count": 1300, "last_updated": "2026-09-30T00:00:00Z"},
		"lockfile": {"dependency-count": 397},
		"settings": {"ignore": []},
		"vulnerabilities": {"found": bool(findings), "count": len(findings), "list": findings},
		"warnings": warnings or {},
	}


def _run_dir(directory: Path, *extra_args: str) -> dict:
	"""Run combine against a directory of audit-json-<ref>/audit.json files."""
	proc = subprocess.run(
		[sys.executable, str(COMBINE_PY), str(directory), "--no-lookup", *extra_args],
		capture_output=True,
		text=True,
		check=False,
		cwd=str(REPO_ROOT),
	)
	if proc.returncode != 0:
		raise AssertionError(f"combine failed: {proc.stdout} {proc.stderr}")
	return json.loads(proc.stdout)


def _write_artifact(directory: Path, ref: str, audit_document: dict) -> Path:
	"""Drop a `audit-json-<ref>/audit.json` file into `directory`."""
	subdir = directory / f"audit-json-{ref}"
	subdir.mkdir(parents=True, exist_ok=True)
	path = subdir / "audit.json"
	path.write_text(json.dumps(audit_document), encoding="utf-8")
	return path


class TestClean(unittest.TestCase):
	"""`vulnerabilities.found == false` yields the clean shape."""

	def test_empty_vulnerabilities_exits_zero_and_is_clean(self) -> None:
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", _audit([]))
			out = _run_dir(directory)
		self.assertTrue(out["clean"])
		self.assertIsNone(out["title"])
		self.assertIsNone(out["body"])

	def test_found_false_with_empty_list_is_clean(self) -> None:
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(
				directory,
				"main",
				{"vulnerabilities": {"found": False, "count": 0, "list": []}},
			)
			out = _run_dir(directory)
		self.assertTrue(out["clean"])


class TestDirty(unittest.TestCase):
	"""A non-empty `vulnerabilities.list` yields a deterministic title and body."""

	def test_single_advisory_title_lists_its_id(self) -> None:
		findings = [_vulnerability("RUSTSEC-2026-0338", "quinn-proto", "0.11.18", [">=0.11.19"])]
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", _audit(findings))
			out = _run_dir(directory)
		self.assertFalse(out["clean"])
		self.assertEqual(out["title"], "Dependency advisories: RUSTSEC-2026-0338")
		self.assertIsNotNone(out["body"])
		self.assertIn("`develop`", out["body"])
		self.assertIn("RUSTSEC-2026-0338", out["body"])
		self.assertIn("quinn-proto", out["body"])

	def test_multiple_advisories_sort_ids_in_title(self) -> None:
		findings = [
			_vulnerability("RUSTSEC-2026-0343", "quinn-proto", "0.11.18", [">=0.11.19"]),
			_vulnerability("RUSTSEC-2026-0338", "quinn-proto", "0.11.18", [">=0.11.19"]),
			_vulnerability("RUSTSEC-2026-0340", "quinn-proto", "0.11.18", [">=0.11.19"]),
		]
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "main", _audit(findings))
			out = _run_dir(directory)
		self.assertEqual(
			out["title"],
			"Dependency advisories: RUSTSEC-2026-0338, RUSTSEC-2026-0340, RUSTSEC-2026-0343",
		)

	def test_two_refs_with_the_same_advisory_dedup_to_one_id(self) -> None:
		# When both develop and main hit RUSTSEC-2026-0338, the combined
		# title reads "RUSTSEC-2026-0338" once.
		findings = [_vulnerability("RUSTSEC-2026-0338", "quinn-proto", "0.11.18", [">=0.11.19"])]
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", _audit(findings))
			_write_artifact(directory, "main", _audit(findings))
			out = _run_dir(directory)
		self.assertEqual(out["title"], "Dependency advisories: RUSTSEC-2026-0338")

	def test_two_refs_with_disjoint_advisories_concatenate_ids(self) -> None:
		a = [_vulnerability("RUSTSEC-2026-0338", "quinn-proto", "0.11.18", [">=0.11.19"])]
		b = [_vulnerability("RUSTSEC-2026-0340", "quinn-proto", "0.11.18", [">=0.11.19"])]
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", _audit(a))
			_write_artifact(directory, "main", _audit(b))
			out = _run_dir(directory)
		self.assertEqual(
			out["title"],
			"Dependency advisories: RUSTSEC-2026-0338, RUSTSEC-2026-0340",
		)

	def test_one_clean_ref_with_one_dirty_ref_uses_only_the_dirty_data(self) -> None:
		# develop clean; main dirty. The combine output must reflect only
		# the dirty report, otherwise the title would read "clean: True"
		# even though main failed.
		dirty = [_vulnerability("RUSTSEC-2026-0338", "quinn-proto", "0.11.18", [">=0.11.19"])]
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", _audit([]))
			_write_artifact(directory, "main", _audit(dirty))
			out = _run_dir(directory)
		self.assertFalse(out["clean"])
		self.assertEqual(out["title"], "Dependency advisories: RUSTSEC-2026-0338")

	def test_yanked_warning_appears_in_combined_title(self) -> None:
		# A yanked crate has no RUSTSEC id; the synthetic id keeps the
		# title deterministic.
		warnings = {
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
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", _audit([], warnings))
			_write_artifact(directory, "main", _audit([], warnings))
			out = _run_dir(directory)
		self.assertEqual(out["title"], "Dependency advisories: yanked:stale@0.1.0")

	def test_advisory_without_patched_version_still_admitted(self) -> None:
		findings = [_vulnerability("RUSTSEC-2026-9999", "ghost", "9.9.9", [])]
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", _audit(findings))
			out = _run_dir(directory)
		self.assertIn("no fixed version recorded", out["body"])


class TestFailureIssue(unittest.TestCase):
	"""When the reusable failed without surfacing advisories, the
	combine script builds a `Rust audit failed on <refs>` issue so an
	operator still has a loud signal."""

	def _run_with_run_url(self, directory: Path, run_url: str) -> dict:
		return _run_dir(directory, "--run-url", run_url)

	def test_clean_with_run_url_produces_failure_issue(self) -> None:
		# Two empty per-ref directories mimic a reusable that crashed
		# before it could write JSON for either ref.
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			(directory / "audit-json-develop").mkdir()
			(directory / "audit-json-main").mkdir()
			out = self._run_with_run_url(
				directory, "https://example.com/runs/42"
			)
		self.assertTrue(out["clean"])
		self.assertEqual(
			out["title"], "Rust audit failed on develop, main"
		)
		self.assertIn("https://example.com/runs/42", out["body"])
		self.assertIn("not an advisory", out["body"])

	def test_clean_with_run_url_names_only_failed_refs(self) -> None:
		# develop produced JSON (succeeded); main did not (failed
		# without writing JSON). The failure title must name only `main`,
		# because that is the ref whose failure the operator needs to
		# chase.
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", _audit([]))
			(directory / "audit-json-main").mkdir()
			out = self._run_with_run_url(
				directory, "https://example.com/runs/43"
			)
		self.assertTrue(out["clean"])
		self.assertEqual(out["title"], "Rust audit failed on main")
		self.assertIn("https://example.com/runs/43", out["body"])

	def test_dirty_with_run_url_keeps_advisory_title(self) -> None:
		# An advisory-bearing input must still take the advisory path,
		# even with --run-url. The brief is explicit: the failure issue
		# is for non-advisory failures only.
		findings = [_vulnerability("RUSTSEC-2026-0338", "quinn-proto", "0.11.18", [">=0.11.19"])]
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "main", _audit(findings))
			out = self._run_with_run_url(
				directory, "https://example.com/runs/44"
			)
		self.assertFalse(out["clean"])
		self.assertEqual(
			out["title"], "Dependency advisories: RUSTSEC-2026-0338"
		)

	def test_clean_without_run_url_stays_clean(self) -> None:
		# Without --run-url, a clean combine is the close signal. The
		# script must not invent a failure issue on its own.
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", _audit([]))
			out = _run_dir(directory)
		self.assertTrue(out["clean"])
		self.assertIsNone(out["title"])
		self.assertIsNone(out["body"])


class TestUnreadableInput(unittest.TestCase):
	"""A bad input must fail loud, never emit a clean shape."""

	def test_missing_directory_exits_two(self) -> None:
		proc = subprocess.run(
			[
				sys.executable,
				str(COMBINE_PY),
				os.path.join(tempfile.gettempdir(), "does-not-exist-combine"),
				"--no-lookup",
			],
			capture_output=True,
			text=True,
			check=False,
			cwd=str(REPO_ROOT),
		)
		self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)

	def test_malformed_json_in_artifact_exits_two(self) -> None:
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			subdir = directory / "audit-json-develop"
			subdir.mkdir()
			(subdir / "audit.json").write_text("{not json", encoding="utf-8")
			proc = subprocess.run(
				[sys.executable, str(COMBINE_PY), str(directory), "--no-lookup"],
				capture_output=True,
				text=True,
				check=False,
				cwd=str(REPO_ROOT),
			)
		self.assertEqual(proc.returncode, 2, msg=proc.stdout + proc.stderr)


if __name__ == "__main__":
	unittest.main()
