//! Resolve the argv `epistle stack update` runs against the
//! compose file. The default compose file (host binary on the
//! distroless base) only needs the `mail` service restarted:
//! the .deb replaced `/usr/bin/epistle` on the host and the
//! bind-mount carries the new bytes into the running container.
//! Custom-image mode keeps the old `pull + up -d` shape so the
//! operator can publish a fresh image and have the stack pick
//! it up.
//!
//! The legacy `rewrite_default_image` helper lived here; the
//! logic it carried (rewriting a managed image to the build-time
//! CLI version) no longer exists because the default image is the
//! unchanging distroless base. The marker still does its job:
//! indicating which mode the file is in.

use std::path::Path;

/// One podup invocation: the program name (`podup`, elided by
/// the caller) plus the arguments it sees on its argv. Returned
/// one entry per step the caller must execute, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Step(pub Vec<String>);

/// Read the compose file at `compose` and decide which
/// `podup` argv the update command runs against. The function
/// returns `Err(String)` when the file cannot be read or parsed
/// so the caller surfaces a one-line error and returns
/// `ExitCode::FAILURE`; `Ok(Vec<Step>)` is the argv the caller
/// feeds into `podup -f <compose> <step>` one step at a time.
///
/// The default mode (host binary on the distroless base) emits
/// one step: `restart mail`. The host binary is bind-mounted and
/// a fresh .deb replaces it; restarting the service picks up
/// the new bytes without pulling anything from a registry.
///
/// Custom-image mode (operator pinned their own image) keeps the
/// `pull + up -d` shape the old code used. `pull` is a no-op
/// when the operator's tag has not changed (idempotent on the
/// daemon) and `up -d` recreates the container with the freshly
/// pulled layers.
pub(super) fn stack_update_steps(compose: &Path) -> Result<Vec<Step>, String> {
	let bytes = std::fs::read(compose)
		.map_err(|error| format!("cannot read {}: {error}", compose.display()))?;
	let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
		format!(
			"{} is not a valid JSON compose file: {error}",
			compose.display()
		)
	})?;
	let managed = value
		.get("x-epistle-managed-image")
		.and_then(serde_json::Value::as_bool)
		.unwrap_or(false);
	if managed {
		// Default compose: the distroless base never moves
		// between releases, so a `pull` would be wasted I/O.
		// The .deb replaced the host binary and the bind-mount
		// will hand the new bytes to the next start; restart
		// the mail service to pick them up.
		Ok(vec![Step(vec!["restart".to_string(), "mail".to_string()])])
	} else {
		// Custom image: the operator owns the image. `pull`
		// updates the local cache to whatever the operator's
		// reference currently resolves to; `up -d` recreates
		// the changed service while keeping volumes and the
		// bind-mounts.
		Ok(vec![
			Step(vec!["pull".to_string()]),
			Step(vec!["up".to_string(), "-d".to_string()]),
		])
	}
}

#[cfg(test)]
#[path = "stack_update_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stack_update_steps_tests.rs"]
mod tests_steps;
