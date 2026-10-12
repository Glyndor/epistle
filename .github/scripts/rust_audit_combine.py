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

When `--run-url` is passed, a clean combine (no advisories in any
input) becomes a non-advisory failure issue. The title is
`Rust audit failed on <refs>` and the body points at the run URL,
with a note that the failure is not an advisory. The workflow runs
this script only when the reusable already failed (`if: failure()`),
so a clean combine output here means a non-advisory failure happened
somewhere in the reusable and operators still need a loud signal.

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
import subprocess
import sys
from pathlib import Path


LABELS = ["type:security", "type:deps", "prio:P1", "area:meta"]

_FAILURE_TITLE_PREFIX = "Rust audit failed on "


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


def failure_issue(reports_dir: Path, run_url: str) -> dict:
	"""Build the issue the workflow opens when the reusable failed
	without surfacing advisories.

	The title names the refs that did not produce JSON: an `audit-json-<ref>`
	subdirectory without an `audit.json` inside it points at a reusable
	that crashed before it could write the JSON (tool install error,
	missing lockfile, etc.). The body names the run URL and says the
	failure is not an advisory, so an operator does not chase a phantom
	vulnerable crate.
	"""
	failed_refs: list[str] = []
	if reports_dir.exists():
		for entry in sorted(reports_dir.iterdir()):
			if not entry.is_dir() or not entry.name.startswith("audit-json-"):
				continue
			if not (entry / "audit.json").exists():
				ref = entry.name[len("audit-json-"):]
				failed_refs.append(ref or "<pr head>")
	title = _FAILURE_TITLE_PREFIX + (
		", ".join(failed_refs) if failed_refs else "audit"
	)
	body = (
		"The daily cargo audit run failed without reporting advisories.\n\n"
		"The reusable workflow exited non-zero but the JSON the combine step "
		"read listed no advisories. That points at a non-advisory failure: "
		"cargo-deny policy, tool install error, missing lockfile, or a JSON "
		"shape the combine script does not understand.\n\n"
		f"Run URL: {run_url}\n\n"
		"This issue is not an advisory; the audit step itself did not flag a "
		"vulnerable crate. Investigate the run linked above."
	)
	return {
		"clean": True,
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
	exists. The lookup uses `gh issue list --label ...` (the `gh`
	wrapper handles pagination), then filters the result by exact title
	in Python. Filtering locally keeps the title comparison exact
	rather than relying on `gh` substring search, which would match
	"Dependency advisories: RUSTSEC-2026-0338" against an issue titled
	"Dependency advisories: RUSTSEC-2026-0338, RUSTSEC-2026-0340".
	"""
	cmd = [
		"gh",
		"issue",
		"list",
		"--repo",
		repo,
		"--state",
		"open",
		"--json",
		"number,title",
	]
	for label in LABELS:
		cmd += ["--label", label]
	result = subprocess.run(
		cmd,
		input="",
		capture_output=True,
		text=True,
		check=False,
	)
	if result.returncode != 0:
		# `gh` exits non-zero on auth failure or network error. The
		# workflow needs to open a new issue in that case, so we return
		# empty rather than fail the whole combine step.
		return ""
	try:
		issues = json.loads(result.stdout)
	except json.JSONDecodeError:
		return ""
	for issue in issues:
		if issue.get("title") == title:
			return str(issue.get("number", ""))
	return ""


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
	parser.add_argument(
		"--run-url",
		default="",
		help=(
			"URL of the workflow run. When set, a clean combine (no "
			"advisories) is turned into a non-advisory failure issue "
			"with the URL in the body."
		),
	)
	return parser.parse_args(argv)


def main(argv: list[str]) -> int:
	args = _parse_args(argv)
	try:
		if args.reports_dir == "-":
			reports = _read_reports_from_stdin()
			reports_dir = Path("-")
		else:
			reports_dir = Path(args.reports_dir)
			reports = _read_reports_from_dir(reports_dir)
	except ValueError as exc:
		print(f"rust_audit_combine: {exc}", file=sys.stderr)
		return 2
	combined = combine(reports)
	if combined["clean"] and args.run_url:
		combined = failure_issue(reports_dir, args.run_url)
	if (
		not combined["clean"]
		or (combined["clean"] and args.run_url)
	) and args.repo and not args.no_lookup:
		combined["existing"] = lookup_existing(args.repo, combined["title"] or "")
	json.dump(combined, sys.stdout, indent=2, sort_keys=True)
	sys.stdout.write("\n")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
