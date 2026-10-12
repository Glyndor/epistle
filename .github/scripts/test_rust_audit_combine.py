#!/usr/bin/env python3
"""Tests for `.github/scripts/rust_audit_combine.py`.

Run from the repository root with:

	python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v

Drives the script as an external command over a directory of fake
artifacts, the way the workflow downloads them. Every assertion is on a
JSON value the script emits; nothing depends on a sentence in the body,
so wording changes that keep the fields intact cannot break a test.

The `--no-lookup` flag covers everything except the `gh api` call,
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


def _run_json(text: dict) -> dict:
	"""Pass one report on stdin, return the parsed stdout."""
	proc = subprocess.run(
		[sys.executable, str(COMBINE_PY), "-", "--no-lookup"],
		input=json.dumps(text),
		capture_output=True,
		text=True,
		check=False,
		cwd=str(REPO_ROOT),
	)
	if proc.returncode != 0:
		raise AssertionError(f"combine failed: {proc.stdout} {proc.stderr}")
	return json.loads(proc.stdout)


def _run_dir(directory: Path) -> dict:
	"""Run combine against a directory of audit-json-<ref>/audit.json files."""
	proc = subprocess.run(
		[sys.executable, str(COMBINE_PY), str(directory), "--no-lookup"],
		capture_output=True,
		text=True,
		check=False,
		cwd=str(REPO_ROOT),
	)
	if proc.returncode != 0:
		raise AssertionError(f"combine failed: {proc.stdout} {proc.stderr}")
	return json.loads(proc.stdout)


def _report(
	ref: str,
	*,
	clean: bool,
	title: str | None = None,
	body: str | None = None,
) -> dict:
	"""Build a fake per-ref report. `clean: true` ignores title/body."""
	if clean:
		return {"ref": ref, "clean": True, "title": None, "body": None, "advisories": []}
	return {
		"ref": ref,
		"clean": False,
		"title": title,
		"body": body,
		"advisories": [],
	}


def _write_artifact(directory: Path, ref: str, report: dict) -> Path:
	"""Drop a `audit-json-<ref>/audit.json` file into `directory`."""
	subdir = directory / f"audit-json-{ref}"
	subdir.mkdir(parents=True, exist_ok=True)
	path = subdir / "audit.json"
	path.write_text(json.dumps(report), encoding="utf-8")
	return path


class TestCombine(unittest.TestCase):
	"""Single-ref and multi-ref aggregation rules."""

	def test_clean_input_is_clean(self) -> None:
		out = _run_json(_report("develop", clean=True))
		self.assertTrue(out["clean"])
		self.assertIsNone(out["title"])
		self.assertIsNone(out["body"])
		self.assertEqual(out["existing"], "")

	def test_single_dirty_ref_yields_its_title_and_body(self) -> None:
		report = _report(
			"develop",
			clean=False,
			title="Dependency advisories: RUSTSEC-2026-0338",
			body="### RUSTSEC-2026-0338 - quinn-proto 0.11.18",
		)
		out = _run_json(report)
		self.assertFalse(out["clean"])
		self.assertEqual(out["title"], "Dependency advisories: RUSTSEC-2026-0338")
		self.assertIn("quinn-proto 0.11.18", out["body"])
		self.assertEqual(out["existing"], "")

	def test_two_refs_with_the_same_advisory_dedup_to_one_id(self) -> None:
		# When both develop and main hit RUSTSEC-2026-0338, the combined
		# title reads "RUSTSEC-2026-0338" once. A duplicate id would
		# produce a redundant issue title and confuse the open-or-comment
		# lookup if the dedupe ran out of order.
		report_a = _report(
			"develop",
			clean=False,
			title="Dependency advisories: RUSTSEC-2026-0338",
			body="body for develop",
		)
		report_b = _report(
			"main",
			clean=False,
			title="Dependency advisories: RUSTSEC-2026-0338",
			body="body for main",
		)
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", report_a)
			_write_artifact(directory, "main", report_b)
			out = _run_dir(directory)
		self.assertEqual(out["title"], "Dependency advisories: RUSTSEC-2026-0338")
		self.assertIn("body for develop", out["body"])
		self.assertIn("body for main", out["body"])

	def test_two_refs_with_disjoint_advisories_concatenate_ids(self) -> None:
		# develop sees A; main sees B. The combined title must carry both,
		# sorted. A flaky sort here would put `,` between ids and a
		# comment on the same issue would diff every time the order
		# changed.
		report_a = _report(
			"develop",
			clean=False,
			title="Dependency advisories: RUSTSEC-2026-0338",
			body="body for develop",
		)
		report_b = _report(
			"main",
			clean=False,
			title="Dependency advisories: RUSTSEC-2026-0340",
			body="body for main",
		)
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", report_a)
			_write_artifact(directory, "main", report_b)
			out = _run_dir(directory)
		self.assertEqual(
			out["title"],
			"Dependency advisories: RUSTSEC-2026-0338, RUSTSEC-2026-0340",
		)

	def test_one_clean_ref_with_one_dirty_ref_uses_only_the_dirty_data(self) -> None:
		# develop clean; main dirty. The combine output must reflect only
		# the dirty report, otherwise the title would read "clean: True"
		# even though main failed.
		clean = _report("develop", clean=True)
		dirty = _report(
			"main",
			clean=False,
			title="Dependency advisories: RUSTSEC-2026-0338",
			body="main is dirty",
		)
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", clean)
			_write_artifact(directory, "main", dirty)
			out = _run_dir(directory)
		self.assertFalse(out["clean"])
		self.assertEqual(out["title"], "Dependency advisories: RUSTSEC-2026-0338")
		self.assertIn("main is dirty", out["body"])

	def test_yanked_warning_appears_in_combined_title(self) -> None:
		# Synthetic ids for warnings keep their `kind:crate@version` form
		# so the title is still a deterministic key.
		report_a = _report(
			"develop",
			clean=False,
			title="Dependency advisories: yanked:stale@0.1.0",
			body="stale is yanked",
		)
		report_b = _report(
			"main",
			clean=False,
			title="Dependency advisories: yanked:stale@0.1.0",
			body="stale is yanked on main too",
		)
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", report_a)
			_write_artifact(directory, "main", report_b)
			out = _run_dir(directory)
		self.assertEqual(out["title"], "Dependency advisories: yanked:stale@0.1.0")


class TestFailureIssue(unittest.TestCase):
	"""When the reusable failed without surfacing advisories, the
	combine script builds a `Rust audit failed on <refs>` issue so an
	operator still has a loud signal."""

	def _run_with_run_url(self, directory: Path, run_url: str) -> dict:
		proc = subprocess.run(
			[
				sys.executable,
				str(COMBINE_PY),
				str(directory),
				"--no-lookup",
				"--run-url",
				run_url,
			],
			capture_output=True,
			text=True,
			check=False,
			cwd=str(REPO_ROOT),
		)
		if proc.returncode != 0:
			raise AssertionError(f"combine failed: {proc.stdout} {proc.stderr}")
		return json.loads(proc.stdout)

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
		# chase. Naming both would muddle that signal.
		clean_report = _report("develop", clean=True)
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", clean_report)
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
		dirty = _report(
			"main",
			clean=False,
			title="Dependency advisories: RUSTSEC-2026-0338",
			body="quinn-proto 0.11.18",
		)
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "main", dirty)
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
		clean_report = _report("develop", clean=True)
		with tempfile.TemporaryDirectory() as tmp:
			directory = Path(tmp)
			_write_artifact(directory, "develop", clean_report)
			proc = subprocess.run(
				[sys.executable, str(COMBINE_PY), str(directory), "--no-lookup"],
				capture_output=True,
				text=True,
				check=False,
				cwd=str(REPO_ROOT),
			)
		self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
		out = json.loads(proc.stdout)
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
