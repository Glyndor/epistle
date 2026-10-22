#!/usr/bin/env python3
"""Combine one or more `cargo audit --json` outputs into the JSON the
rust-audit workflow consumes to open or comment on an issue.

The workflow downloads every `audit-json-<ref>` artifact the matrix
produced and feeds them in. Each artifact is a raw `cargo audit --json`
document (`vulnerabilities.list[]`, `warnings.<kind>[]`, etc.); this
script normalizes every per-ref document, folds them into one object,
and emits:

	{
	  "clean": true|false,
	  "title": "Dependency advisories: RUSTSEC-..., yanked:foo@...",
	  "body": "...concatenated bodies separated by ---...",
	  "existing": "<issue number> or empty"
	}

`existing` is the number of an already-open issue with the same title
and the matching label set, or the empty string when none exists. The
workflow uses it to decide whether to open a new issue or comment on
the one it already has. The script only emits the lookup; the `gh`
call is in the workflow so the GitHub token stays in the step's
`env:` block.

When `--run-url` is passed, a clean combine (no advisories in any
input) becomes a non-advisory failure issue. The title is
`Rust audit failed on <refs>` and the body points at the run URL,
with a note that the failure is not an advisory. The workflow runs
this script only when the reusable already failed (`if: failure()`),
so a clean combine output here means a non-advisory failure happened
somewhere in the reusable and operators still need a loud signal.

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

_BODY_TEMPLATE = """\
Dependency advisories open against {ref}.

This issue is opened automatically by the `rust-audit` workflow on the
`{ref}` ref. The next run on both `develop` and `main` that finds no
advisories closes it.

{per_advisory}

Advisories in dependencies are public, so a public issue is fine.
"""


def _per_advisory(advisories: list[dict]) -> str:
	"""Render the per-advisory markdown, sorted by id for a stable diff."""
	lines: list[str] = []
	for advisory in sorted(advisories, key=lambda a: a["id"]):
		heading = f"### {advisory['id']} - {advisory['package']} {advisory['version']}"
		lines.append(heading)
		lines.append(f"- Kind: `{advisory['kind']}`")
		if advisory["patched"]:
			lines.append(f"- Patched in: `{advisory['patched']}`")
		else:
			lines.append("- Patched in: _no fixed version recorded_")
		refs = ", ".join(f"`{ref}`" for ref in sorted(advisory["refs"]))
		lines.append(f"- Found on: {refs}")
		lines.append("")
	return "\n".join(lines)


def _vulnerability_advisory(vulnerability: dict, ref: str) -> dict:
	"""Map one cargo-audit vulnerability entry to the workflow's shape."""
	advisory = vulnerability.get("advisory") or {}
	versions = vulnerability.get("versions") or {}
	package = vulnerability.get("package") or {}
	patched = versions.get("patched") or []
	return {
		"id": str(advisory.get("id", "")),
		"kind": "vulnerability",
		"package": str(package.get("name", "")),
		"version": str(package.get("version", "")),
		"patched": str(patched[0]) if patched else "",
		"refs": [ref],
	}


def _warning_advisory(warning: dict, ref: str) -> dict:
	"""Map one cargo-audit warning entry to the workflow's shape.

	A warning without a RUSTSEC id (a yanked crate, for example) gets a
	synthesised id of the form `<kind>:<crate>@<version>`. The id never
	collides with a real RUSTSEC id (those are `RUSTSEC-YYYY-NNNN`).
	"""
	advisory = warning.get("advisory") or {}
	package = warning.get("package") or {}
	versions = warning.get("versions") or {}
	raw_id = advisory.get("id", "")
	kind = str(warning.get("kind", ""))
	package_name = str(package.get("name", ""))
	package_version = str(package.get("version", ""))
	synthetic_id = f"{kind}:{package_name}@{package_version}" if kind and package_name and package_version else ""
	synth_id = str(raw_id) if raw_id else synthetic_id
	patched = (versions.get("patched") or []) if isinstance(versions, dict) else []
	return {
		"id": synth_id,
		"kind": kind or "warning",
		"package": package_name,
		"version": package_version,
		"patched": str(patched[0]) if patched else "",
		"refs": [ref],
	}


def _collect_warnings(document: dict, ref: str) -> list[dict]:
	"""Flatten the `warnings` map into the advisories shape.

	The cargo-audit JSON puts warnings under `warnings.<kind>[]`; we collect
	them into one list so the title and body treat every finding the same
	way.
	"""
	warnings = document.get("warnings")
	if not isinstance(warnings, dict):
		return []
	out: list[dict] = []
	for kind, entries in warnings.items():
		if not isinstance(entries, list):
			continue
		for entry in entries:
			if not isinstance(entry, dict):
				continue
			out.append(_warning_advisory(entry, ref))
	return out


def parse_audit_json(audit_json_text: str, ref: str) -> dict:
	"""Parse one cargo-audit JSON document into the workflow's shape.

	Raises `ValueError` on missing required fields. The script exits 2 on
	that, which the workflow reads as a step failure rather than as a
	missing-advisories state. A report without the `vulnerabilities` key
	is treated as malformed: treating it as clean would silently close an
	open advisory issue if cargo-audit's output format ever changed.
	"""
	try:
		document = json.loads(audit_json_text)
	except json.JSONDecodeError as exc:
		raise ValueError(f"audit JSON is not valid JSON: {exc}") from exc
	if not isinstance(document, dict):
		raise ValueError("audit JSON must be an object")
	if "vulnerabilities" not in document:
		raise ValueError("audit JSON is missing the `vulnerabilities` field")
	vulnerabilities = document["vulnerabilities"]
	if not isinstance(vulnerabilities, dict):
		raise ValueError("audit JSON `vulnerabilities` must be an object")
	findings = vulnerabilities.get("list") or []
	if not isinstance(findings, list):
		raise ValueError("audit JSON `vulnerabilities.list` must be an array")

	advisories: list[dict] = [_vulnerability_advisory(entry, ref) for entry in findings]
	advisories.extend(_collect_warnings(document, ref))
	clean = vulnerabilities.get("found") is False and not advisories
	if clean:
		return {
			"ref": ref,
			"clean": True,
			"title": None,
			"body": None,
			"advisories": [],
		}

	ids = sorted({a["id"] for a in advisories if a["id"]})
	title = "Dependency advisories: " + ", ".join(ids) if ids else None
	body = _BODY_TEMPLATE.format(ref=ref, per_advisory=_per_advisory(advisories))
	return {
		"ref": ref,
		"clean": False,
		"title": title,
		"body": body,
		"advisories": advisories,
	}


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
	"""Find every JSON report in an `audit-json-<ref>/` subdirectory of
	`directory` and normalize each one via `parse_audit_json`.

	The ref is taken from the directory name (`audit-json-develop` ->
	`develop`). Inside it, `audit.json` is the ref's own workspace and a
	report named after another one (`audit-fuzz-Cargo.json`) is a second
	workspace of the same ref, which the label carries as
	`<ref>/<workspace>` so the issue says which graph the advisory came
	from.
	"""
	if not directory.exists():
		raise ValueError(f"{directory} does not exist; the artifact download is stale")
	if not directory.is_dir():
		raise ValueError(f"{directory} is not a directory")
	reports: list[dict] = []
	for ref_dir in sorted(directory.glob("audit-json-*")):
		ref = ref_dir.name[len("audit-json-"):]
		for path in sorted(ref_dir.glob("*.json")):
			label = ref
			if path.name != "audit.json":
				stem = path.stem
				workspace = stem[len("audit-"):] if stem.startswith("audit-") else stem
				label = f"{ref}/{workspace}" if ref else workspace
			try:
				text = path.read_text(encoding="utf-8")
			except OSError as exc:
				raise ValueError(f"cannot read {path}: {exc}") from exc
			reports.append(parse_audit_json(text, label))
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
		help="Directory the workflow downloaded the audit-json-<ref>/ artifacts into.",
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
		reports_dir = Path(args.reports_dir)
		reports = _read_reports_from_dir(reports_dir)
	except ValueError as exc:
		print(f"rust_audit_combine: {exc}", file=sys.stderr)
		return 2
	combined = combine(reports)
	if combined["clean"] and args.run_url:
		combined = failure_issue(reports_dir, args.run_url)
	lookup_title = combined["title"] or ""
	if (
		(combined["clean"] and args.run_url)
		or not combined["clean"]
	) and args.repo and not args.no_lookup:
		combined["existing"] = lookup_existing(args.repo, lookup_title)
	json.dump(combined, sys.stdout, indent=2, sort_keys=True)
	sys.stdout.write("\n")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
