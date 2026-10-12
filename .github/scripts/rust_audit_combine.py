#!/usr/bin/env python3
"""Combine one or more `rust_audit_report.py` outputs into the JSON the
rust-audit workflow consumes to open or comment on an issue.

The workflow downloads every `audit-json-<ref>` artifact the matrix
produced and feeds them in. Each input is the JSON the parser wrote
(its own object, see `.github/scripts/rust_audit_report.py`). The
combined shape:

	{
	  "clean": true|false,
	  "title": "Dependency advisories: RUSTSEC-..., yanked:foo@...",
	  "body": "...concatenated bodies separated by ---...",
	  "existing": "<issue number> or empty"
	}

`existing` is the number of an already-open issue with the same title
and the matching label set, or the empty string when none exists. The
workflow uses it to decide whether to open a new issue or comment on the
one it already has. The script only emits the lookup; the `gh` call is
in the workflow so the GitHub token stays in the step's `env:` block.

Usage:
	rust_audit_combine.py <reports-dir>
	rust_audit_combine.py -                # read JSONL from stdin

A clean report (every input's `clean` is true and the combined body is
empty) exits 0 with a clean shape; the workflow reads it as the close
signal. The body is empty only when every input was clean, because a
dirty input always has a body to contribute.

Exit codes:
	0  reports combined
	2  the inputs could not be read or parsed
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


LABELS = ["type:security", "type:deps", "prio:P1", "area:meta"]


def combine(reports: list[dict]) -> dict:
	"""Fold the per-ref reports into one combined object."""
	combined_ids: set[str] = set()
	combined_body_parts: list[str] = []
	any_dirty = False
	for report in reports:
		if report.get("clean"):
			continue
		any_dirty = True
		title = report.get("title") or ""
		body = report.get("body") or ""
		# Title shape: "Dependency advisories: A, B, C". Strip the leading
		# prefix to keep only the ids when more than one ref contributes
		# to the combined title.
		if title.startswith("Dependency advisories:"):
			ids = title[len("Dependency advisories:"):].strip()
		else:
			ids = ""
		for ident in (s.strip() for s in ids.split(",")):
			if ident:
				combined_ids.add(ident)
		if body:
			combined_body_parts.append(body)

	if not any_dirty:
		return {"clean": True, "title": None, "body": None, "existing": ""}

	sorted_ids = sorted(combined_ids)
	title = "Dependency advisories: " + ", ".join(sorted_ids) if sorted_ids else "Dependency advisories:"
	body = "\n\n---\n\n".join(combined_body_parts)
	return {
		"clean": False,
		"title": title,
		"body": body,
		"existing": "",  # filled in by `lookup_existing`
	}


def _read_reports_from_dir(directory: Path) -> list[dict]:
	"""Find every per-ref report in `directory` and parse it."""
	if not directory.exists():
		raise ValueError(f"{directory} does not exist; the artifact download is stale")
	if not directory.is_dir():
		raise ValueError(f"{directory} is not a directory")
	reports: list[dict] = []
	for path in sorted(directory.glob("audit-json-*/audit.json")):
		try:
			text = path.read_text(encoding="utf-8")
		except OSError as exc:
			raise ValueError(f"cannot read {path}: {exc}") from exc
		try:
			report = json.loads(text)
		except json.JSONDecodeError as exc:
			raise ValueError(f"{path} is not valid JSON: {exc}") from exc
		reports.append(report)
	return reports


def _read_reports_from_stdin() -> list[dict]:
	"""Read one JSON object per line from stdin."""
	reports: list[dict] = []
	for line in sys.stdin:
		line = line.strip()
		if not line:
			continue
		try:
			reports.append(json.loads(line))
		except json.JSONDecodeError as exc:
			raise ValueError(f"stdin line is not valid JSON: {exc}") from exc
	return reports


def lookup_existing(repo: str, title: str) -> str:
	"""Find an open issue with `title` and the audit labels.

	Returns the issue number as a string, or an empty string when none
	exists. Filters out pull requests because `gh api repos/.../issues`
	includes them (they have the same shape) and they would otherwise be
	mistaken for a matching advisory issue.
	"""
	label_arg = ",".join(LABELS)
	cmd = [
		"gh",
		"api",
		f"repos/{repo}/issues?state=open&labels={label_arg}&per_page=100",
		"--jq",
		'[.[] | select(.pull_request == null and .title == $TITLE) | .number] | first // empty',
	]
	result = subprocess.run(
		cmd,
		input="",
		capture_output=True,
		text=True,
		check=False,
		env={**os.environ, "TITLE": title},
	)
	if result.returncode != 0:
		# `gh api` exit non-zero on auth failure or network error. The
		# workflow needs to open a new issue in that case, so we return
		# empty rather than fail the whole combine step.
		return ""
	return result.stdout.strip()


def _parse_args(argv: list[str]) -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Combine rust-audit reports and look up an open advisory issue.",
	)
	parser.add_argument(
		"reports_dir",
		nargs="?",
		default="-",
		help="Directory of per-ref audit-json-<ref>/audit.json files, or `-` for stdin",
	)
	parser.add_argument(
		"--repo",
		help="GitHub repo to look up the existing issue in (owner/name)",
	)
	parser.add_argument(
		"--no-lookup",
		action="store_true",
		help="Skip the issue lookup; emit `existing: \"\"`",
	)
	return parser.parse_args(argv)


def main(argv: list[str]) -> int:
	args = _parse_args(argv)
	try:
		if args.reports_dir == "-":
			reports = _read_reports_from_stdin()
		else:
			reports = _read_reports_from_dir(Path(args.reports_dir))
	except ValueError as exc:
		print(f"rust_audit_combine: {exc}", file=sys.stderr)
		return 2
	combined = combine(reports)
	if (
		not combined["clean"]
		and args.repo
		and not args.no_lookup
	):
		combined["existing"] = lookup_existing(args.repo, combined["title"] or "")
	json.dump(combined, sys.stdout, indent=2, sort_keys=True)
	sys.stdout.write("\n")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))