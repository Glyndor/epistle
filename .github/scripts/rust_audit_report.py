#!/usr/bin/env python3
"""Normalize a `cargo audit --json` report into the shape the
rust-audit workflow consumes.

The workflow opens (or comments on) an issue per distinct set of advisories
and closes any stale one when a later run on both refs is clean. To keep
those decisions deterministic, every run must agree on the title for a given
input. The title is the comma-separated, alphabetically sorted list of
advisory ids; the body carries the crate, the installed version, the first
patched version and the ref where the advisory was found.

Usage:
	rust_audit_report.py <audit-json-path> <ref>
	rust_audit_report.py -  <ref>           # read JSON from stdin

The script does no I/O beyond reading its argument. It never calls `gh`,
opens issues, or touches the network; the workflow wraps its output in the
`gh issue` calls. Keeping the parse step pure is what lets
`test_rust_audit_report.py` exercise it without a GitHub token or a
fixture for the API.

Output is a single JSON object on stdout, with this shape:

	{
	  "ref": "main",
	  "clean": false,
	  "title": "Dependency advisories: RUSTSEC-2026-0338, RUSTSEC-2026-0340",
	  "body": "...markdown body naming each advisory, crate, version and patched version...",
	  "advisories": [
	    {
	      "id": "RUSTSEC-2026-0338",
	      "package": "quinn-proto",
	      "version": "0.11.18",
	      "patched": ">=0.11.19",
	      "refs": ["main"]
	    }
	  ]
	}

A clean audit (no `vulnerabilities.list` entries) yields `clean: true`,
`title: null`, `body: null` and an empty advisories list. The workflow
treats that as the close signal for any open issue with the matching labels.

Exit codes:
	0  the report was parsed and emitted
	2  the input could not be read or parsed
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# Body template. Markdown so `gh issue create --body` renders it as-is. The
# per-advisory breakdown is one block per id, sorted, so two consecutive
# issues have a readable diff. The fixed version is the first item from
# `versions.patched`; a more elaborate parser would honour every entry in
# the range, but the issue body is for humans and the first fix is what
# they want to read.
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
		if advisory["patched"]:
			lines.append(f"- Patched in: `{advisory['patched']}`")
		else:
			lines.append("- Patched in: _no fixed version recorded_")
		refs = ", ".join(f"`{ref}`" for ref in sorted(advisory["refs"]))
		lines.append(f"- Found on: {refs}")
		lines.append("")
	return "\n".join(lines)


def _advisory(vulnerability: dict, ref: str) -> dict:
	"""Pull the fields the issue body needs out of one vulnerability entry.

	The entry is the JSON object `cargo audit --json` emits per finding; the
	advisory id and metadata live on `.advisory`, the installed version on
	`.package.version`, and the patched range on `.versions.patched` (a list
	of version-req strings, e.g. `">=1.2.3"`).
	"""
	advisory = vulnerability.get("advisory") or {}
	versions = vulnerability.get("versions") or {}
	package = vulnerability.get("package") or {}
	patched = versions.get("patched") or []
	return {
		"id": str(advisory.get("id", "")),
		"package": str(package.get("name", "")),
		"version": str(package.get("version", "")),
		"patched": str(patched[0]) if patched else "",
		"refs": [ref],
	}


def parse(audit_json_text: str, ref: str) -> dict:
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

	advisories = [_advisory(entry, ref) for entry in findings]
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


def _read_argument(value: str) -> str:
	"""Read JSON from a path, or from stdin when the value is the dash."""
	if value == "-":
		return sys.stdin.read()
	path = Path(value)
	try:
		return path.read_text(encoding="utf-8")
	except OSError as exc:
		raise ValueError(f"cannot read {value}: {exc}") from exc


def _parse_args(argv: list[str]) -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Normalize a cargo audit JSON report for the rust-audit workflow.",
	)
	parser.add_argument(
		"audit_json",
		help="Path to a cargo audit --json file, or `-` for stdin",
	)
	parser.add_argument(
		"ref",
		help="Git ref the audit was run against (e.g. develop, main)",
	)
	return parser.parse_args(argv)


def main(argv: list[str]) -> int:
	args = _parse_args(argv)
	try:
		text = _read_argument(args.audit_json)
		report = parse(text, args.ref)
	except ValueError as exc:
		print(f"rust_audit_report: {exc}", file=sys.stderr)
		return 2
	json.dump(report, sys.stdout, indent=2, sort_keys=True)
	sys.stdout.write("\n")
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))