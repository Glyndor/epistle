//! Path overlap rules between `data_dir` and `config_path`, plus
//! the unresolvable-parent and compose-interpolation refusals.
//! Every test here drives `validate()` with both paths set, and
//! asserts that the validator surfaces the matching `Invalid`
//! before the apply phase would write a key.

use std::path::PathBuf;

use super::Mode::*;
use super::tests::minimal;
use super::*;

/// `config_path` inside `data_dir` would produce a compose file
/// that mounts the same path twice (the data-directory bind
/// mount and the config-directory bind mount land at the same
/// destination), and podman refuses the container at
/// `podup up` time. The validator catches the overlap so the
/// operator sees the refusal before any effect.
#[test]
fn config_path_inside_data_dir_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/var/lib/epistle/etc/mail.toml");
	let errors = answers
		.validate()
		.expect_err("config_path inside data_dir must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigMountsOverlap { .. })),
		"config_path inside data_dir must surface as ConfigMountsOverlap, got {errors:?}"
	);
}

/// The reverse direction: `data_dir` inside `config_path`'s
/// directory would mount the same destination twice in the
/// other order. The validator catches it too.
#[test]
fn data_dir_inside_config_path_parent_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/etc/epistle/data");
	answers.config_path = PathBuf::from("/etc/epistle/mail.toml");
	let errors = answers
		.validate()
		.expect_err("data_dir inside config_path's parent must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigMountsOverlap { .. })),
		"data_dir inside config_path's parent must surface as ConfigMountsOverlap, got {errors:?}"
	);
}

/// Acceptance half of the overlap pair: a `config_path` whose
/// parent is a sibling of `data_dir` (the typical
/// `/var/lib/epistle` and `/etc/epistle` split) must validate.
#[test]
fn config_path_and_data_dir_siblings_validate() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/etc/epistle/mail.toml");
	assert!(
		answers.validate().is_ok(),
		"the standard sibling layout must validate, got {:?}",
		answers.validate()
	);
}

/// Two paths that look textually disjoint but resolve to the same
/// directory through `.` and `..` components must still be caught
/// by the overlap check. The previous shape walked `Path::components`
/// verbatim and saw `spare` and `..` as separate components, so
/// `data_dir = "/srv/epistle/data"` and
/// `config_path = "/srv/epistle/spare/../data/mail.toml"` looked
/// disjoint and slipped past the validator. The compose file
/// would then mount `/srv/epistle/data` on both sides of the
/// colon and podman would refuse the container.
#[test]
fn config_path_resolved_through_parent_dir_is_rejected() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/srv/epistle/data");
	answers.config_path = PathBuf::from("/srv/epistle/spare/../data/mail.toml");
	let errors = answers
		.validate()
		.expect_err("an equivalent config_path must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigMountsOverlap { .. })),
		"lexically equivalent paths must surface as ConfigMountsOverlap, got {errors:?}"
	);
}

/// A `..` that cannot be resolved lexically (the path tries to
/// escape its own root, e.g. `data_dir = "/../foo"`) is refused
/// as `PathParentEscapesRoot`. The validator cannot normalise
/// the path without rewriting it to a location the operator did
/// not type, and silently doing so would land a file where the
/// operator did not look.
#[test]
fn data_dir_with_unresolvable_parent_is_rejected() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/../foo");
	answers.config_path = PathBuf::from("/etc/epistle/mail.toml");
	let errors = answers
		.validate()
		.expect_err("a parent_dir that escapes the root must be rejected");
	assert!(
		errors.iter().any(
			|e| matches!(e, Invalid::PathParentEscapesRoot { field, .. } if field == "data_dir")
		),
		"unresolvable .. must surface as PathParentEscapesRoot, got {errors:?}"
	);
}

/// A `$` inside `data_dir` or `config_path` is a compose-time
/// interpolation token. The compose file mounts both paths
/// verbatim on both sides of the colon, so `podup config`
/// resolves the `$VAR` against the host environment (to the
/// empty string when unset) while the rendered `mail.toml`
/// keeps the literal `$VAR` in its `data` and key paths. The
/// container then cannot find the keys the host generated.
/// The validator refuses the shape as `PathInterpolated`
/// before any effect so the operator has to write the
/// resolved path directly.
#[test]
fn data_dir_with_dollar_is_rejected_as_compose_interpolation() {
	let mut answers = minimal(Manual);
	// The exact input from the report: a `data_dir` that
	// interpolates an unset `TENANT`. `podup config` resolves
	// the mount to `/tmp/mail-/data` while `mail.toml` keeps
	// the literal `$TENANT` in its data and key paths; the
	// container then cannot find the keys the host generated.
	answers.data_dir = PathBuf::from("/tmp/mail-$TENANT/data");
	let errors = answers
		.validate()
		.expect_err("a `data_dir` containing `$` must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::PathInterpolated { field, .. } if field == "data_dir")),
		"interpolated `data_dir` must surface as PathInterpolated, got {errors:?}"
	);
}

#[test]
fn config_path_with_dollar_is_rejected_as_compose_interpolation() {
	let mut answers = minimal(Manual);
	// Same shape on `config_path`: compose would interpolate
	// the `$VAR` in the mount source while `mail.toml` keeps
	// the literal in the `--config` argument. The validator
	// catches the `$` before any effect.
	answers.config_path = PathBuf::from("/etc/$TENANT/mail.toml");
	let errors = answers
		.validate()
		.expect_err("a `config_path` containing `$` must be rejected");
	assert!(
		errors.iter().any(
			|e| matches!(e, Invalid::PathInterpolated { field, .. } if field == "config_path")
		),
		"interpolated `config_path` must surface as PathInterpolated, got {errors:?}"
	);
}
