#!/usr/bin/env python3
"""Print the OCI tags a release should publish for a given version.

Usage:
  image_tags.py <version>

Plain versions like `v0.9.0` (or `0.9.0` without the leading `v`) publish
three tags: the exact `<major>.<minor>.<patch>`, the floating
`<major>.<minor>`, and the rolling `<major>`. The exact tag points at the
build; the other two point at the same manifest list, so a consumer
pinning `0.9` keeps getting patches and a consumer pinning `0` keeps
getting minors.

Prerelease versions like `v1.0.0-rc.1` publish the exact tag only.
Floating tags are suppressed: `0.10.0-rc` would move `:0` onto a release
candidate and `:0.10` onto a candidate for the next patch, and a consumer
pinning `0` would pull the candidate as if it were the next stable
release. The exact tag is enough for an rc, and the floating tags wait
for the stable cut.

Anything else fails. The release job must not publish at all on a tag
the script cannot classify, because what `podman manifest create` and
`podman manifest push` would then do is undefined and the failure shows
up as a half-built manifest list on ghcr.io, which is worse than a
missing release.

Standard library only; no third-party imports on purpose. `release.yml`
runs the script on a vanilla `ubuntu-latest` runner before any of the
apt-installed signing dependencies, and pulling in a venv for a
classifier would be the kind of complexity a future maintainer debugs
at 3 a.m.
"""
import re
import sys

# Anchored regex. `MAJOR.MINOR.PATCH` exactly, with an optional
# `-<prerelease>` captured for the branching below. The prerelease
# follows the same shape as semver: one or more dot-separated
# identifiers, each alphanumerics and dashes. `0.9.0-stuff-yes` does
# not match because the second identifier starts with a dash; that
# is exactly the rejection the trailing-junk test expects. Each
# numeric component is `[0-9]+` with a leading-zero check applied
# afterwards, because the regex engine does not let us say `[0-9]+`
# and `not 0...` in one pattern. Leading zeros on the minor or patch
# are rejected: cargo does not let them through, and a release script
# that re-validates the same input the build did is the right place
# to refuse them.
VERSION_RE = re.compile(
	r"^v?"
	r"(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
	r"(?:-(?P<prerelease>[0-9A-Za-z][0-9A-Za-z-]*(?:\.[0-9A-Za-z][0-9A-Za-z-]*)*))?"
	r"$"
)


def _die(message: str) -> None:
	"""Print `::error::<message>` on stderr and exit 1.

	`::error::` is the GitHub Actions annotation prefix. It renders the
	message in the workflow run UI as a red error line and lets a
	maintainer see at a glance which step the failure came from, without
	parsing free-form output. A `::error::` that does not also exit
	non-zero is a GitHub UI bug, not a successful step, so the two go
	together.
	"""
	print(f"::error::{message}", file=sys.stderr)
	sys.exit(1)


def tags_for(raw: str) -> list[str]:
	"""Classify `raw` and return the tags it should publish, in order.

	Raises `ValueError` on any input that is not `MAJOR.MINOR.PATCH` with
	an optional `-prerelease` and optional leading `v`, or on a numeric
	component with a leading zero (apart from a literal `0` for the
	major). The caller turns the `ValueError` into a `::error::` line
	and a non-zero exit.
	"""
	match = VERSION_RE.match(raw)
	if not match:
		raise ValueError(
			f"'{raw}' is not MAJOR.MINOR.PATCH[-prerelease]; refusing to publish"
		)

	major = match.group("major")
	minor = match.group("minor")
	patch = match.group("patch")
	prerelease = match.group("prerelease")

	# Leading-zero guard. `0` is the only valid single-digit number, and
	# only for the major. A minor of `00` or a patch of `09` are not
	# version strings; a prerelease suffix like `-0` is fine because the
	# regex requires at least one extra character after the dash.
	for name, value in (("major", major), ("minor", minor), ("patch", patch)):
		if len(value) > 1 and value[0] == "0":
			raise ValueError(
				f"'{raw}' has a leading zero in {name}={value}; refusing to publish"
			)

	if prerelease:
		# Prerelease: exact tag only. The minor and major tags are
		# withheld so a `:0` consumer does not leap onto a candidate.
		return [f"{major}.{minor}.{patch}-{prerelease}"]
	return [f"{major}.{minor}.{patch}", f"{major}.{minor}", major]


def main(argv: list[str]) -> int:
	if len(argv) != 1:
		_die(
			"image_tags.py takes one argument, the version to classify "
			f"(got {len(argv)})"
		)
	try:
		for tag in tags_for(argv[0]):
			print(tag)
	except ValueError as exc:
		_die(str(exc))
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
