//! The `podup` version floor `epistle stack` enforces before it runs any
//! subcommand. Split from `mod.rs`.

use std::process::{Command, ExitCode};

use super::exit_code_from_status;

/// The `podup` version this build requires at minimum. Mirrors the
/// `podup (>= 5.15.4)` dependency in `debian/control`; a test reads
/// the control file and asserts the two are equal so the floor cannot
/// drift away from the package relationship.
pub(super) const PODUP_FLOOR: &str = "5.15.4";

/// Spawn `podup --version`, parse the `vMAJOR.MINOR.PATCH` it prints,
/// and refuse to run any subcommand below [`PODUP_FLOOR`]. The error
/// names both the version the host has and the floor, so the operator
/// can tell at a glance which one is wrong. Returns `Ok(())` on
/// success, `Err(ExitCode::FAILURE)` on a missing binary, a parse
/// failure, or a too-old version.
pub(super) fn ensure_podup_floor() -> Result<(), ExitCode> {
	let mut command = Command::new("podup");
	command.arg("--version");
	let output = match command.output() {
		Ok(output) => output,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			crate::cli::style::error(
				"`podup` is required by `epistle stack` but was not found on PATH; \
				 install it with `apt install podup` from apt.glyndor.net",
			);
			return Err(ExitCode::FAILURE);
		}
		Err(error) => {
			crate::cli::style::error(format_args!("cannot run `podup --version`: {error}"));
			return Err(ExitCode::FAILURE);
		}
	};
	if !output.status.success() {
		crate::cli::style::error(format_args!(
			"`podup --version` exited with status {}: the binary on PATH is not a usable podup",
			output.status
		));
		return Err(exit_code_from_status(&output.status));
	}
	let stdout = String::from_utf8_lossy(&output.stdout);
	// The real version is on the last non-empty line: podup prints
	// a leading blank before the banner, so `lines().last()` would
	// land on the trailing empty string and report an empty parse.
	let Some(line) = stdout.lines().rev().find(|line| !line.trim().is_empty()) else {
		crate::cli::style::error("`podup --version` produced no output");
		return Err(ExitCode::FAILURE);
	};
	let Some(version) = line
		.trim()
		.strip_prefix("podup version ")
		.and_then(|rest| rest.strip_prefix('v'))
		.unwrap_or(line.trim())
		.split_whitespace()
		.next()
	else {
		crate::cli::style::error(format_args!(
			"`podup --version` printed a line I cannot read: {line:?}"
		));
		return Err(ExitCode::FAILURE);
	};
	if version_at_least(version, PODUP_FLOOR) {
		Ok(())
	} else {
		crate::cli::style::error(format_args!(
			"`podup` {version} is older than the required floor {PODUP_FLOOR}; \
			 upgrade with `apt install podup` (>= {PODUP_FLOOR})"
		));
		Err(ExitCode::FAILURE)
	}
}

/// Compare two dotted version strings component by component.
/// Returns `true` when `candidate` is at least `floor`. The
/// comparison is numeric per component so `5.10.10` is greater than
/// `5.9.0`; a lexicographic compare would say the opposite.
pub(super) fn version_at_least(candidate: &str, floor: &str) -> bool {
	let Ok(candidate) = parse_version(candidate) else {
		return false;
	};
	let Ok(floor) = parse_version(floor) else {
		return false;
	};
	candidate >= floor
}

pub(super) fn parse_version(input: &str) -> Result<Vec<u64>, std::num::ParseIntError> {
	input.split('.').map(|part| part.parse::<u64>()).collect()
}
