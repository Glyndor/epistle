//! The `podman` command line as an [`Engine`], run as the account that runs
//! the stack so it sees the images and containers `podup` made.

use std::collections::BTreeSet;
use std::process::Command;

use super::Engine;

/// The `podman` on the account's `PATH`.
pub(in crate::cli::stack) struct Podman;

impl Podman {
	/// `podman <args>`, waited for.
	fn run(args: &[&str]) -> Result<std::process::Output, String> {
		Command::new("podman")
			.args(args)
			.output()
			.map_err(|error| format!("cannot run podman: {error}"))
	}

	/// The first line podman printed on stderr, or its exit status.
	fn failure(output: &std::process::Output) -> String {
		let text = String::from_utf8_lossy(&output.stderr);
		let line = text.lines().next().unwrap_or("").trim();
		if line.is_empty() {
			format!("podman exited with {}", output.status)
		} else {
			line.to_string()
		}
	}
}

/// A full image id: 64 hex digits, as `podman` prints it.
fn is_id(text: &str) -> bool {
	text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl Engine for Podman {
	fn image_id(&mut self, reference: &str) -> Result<Option<String>, String> {
		// `exists` answers 1 for an image that is not there and something
		// else for a failure, which `inspect` alone does not tell apart.
		let exists = Self::run(&["image", "exists", reference])?;
		match exists.status.code() {
			Some(0) => {}
			Some(1) => return Ok(None),
			_ => return Err(Self::failure(&exists)),
		}
		let inspect = Self::run(&["image", "inspect", "--format", "{{.Id}}", reference])?;
		if !inspect.status.success() {
			return Err(Self::failure(&inspect));
		}
		let id = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
		if is_id(&id) {
			Ok(Some(id))
		} else {
			Err(format!("podman named the image of {reference} {id:?}"))
		}
	}

	fn used_image_ids(&mut self) -> Result<BTreeSet<String>, String> {
		let listed = Self::run(&[
			"ps",
			"--all",
			"--external",
			"--no-trunc",
			"--format",
			"{{.ImageID}}",
		])?;
		if !listed.status.success() {
			return Err(Self::failure(&listed));
		}
		let ids: BTreeSet<String> = String::from_utf8_lossy(&listed.stdout)
			.lines()
			.map(str::trim)
			.filter(|line| !line.is_empty())
			.map(str::to_string)
			.collect();
		match ids.iter().find(|id| !is_id(id)) {
			Some(odd) => Err(format!("podman listed the image id {odd:?}")),
			None => Ok(ids),
		}
	}

	fn remove(&mut self, id: &str) -> Result<(), String> {
		if !is_id(id) {
			return Err(format!("{id:?} is not an image id"));
		}
		let removed = Self::run(&["rmi", id])?;
		if removed.status.success() {
			Ok(())
		} else {
			Err(Self::failure(&removed))
		}
	}
}
