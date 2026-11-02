//! The real [`SwitchHost`]: the compose file on disk, podup and the keys.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use super::{SwitchHost, Switched, switch};
use crate::config::Config;

/// How long `mail` and `certs` get to come up after the switch: the same
/// bound `stack update` gives a restart.
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

struct StackHost<'a> {
	config: &'a Config,
	compose: &'a Path,
	podup: &'a str,
}

impl SwitchHost for StackHost<'_> {
	fn compose_text(&mut self) -> Result<String, String> {
		let bytes = crate::cli::init::compose_read::read(self.compose)?.ok_or_else(|| {
			format!(
				"cannot read {}: there is no such file",
				self.compose.display()
			)
		})?;
		String::from_utf8(bytes)
			.map_err(|_| format!("{} is not valid UTF-8", self.compose.display()))
	}

	fn render(&mut self, existing: &str, on: bool) -> Result<String, String> {
		crate::cli::init::regenerate_with(
			&self.config.data_dir,
			&self.config.listeners,
			existing,
			Some(on),
		)
		.map(|regenerated| regenerated.text)
	}

	fn place_keys(&mut self, on: bool) -> Result<Vec<String>, String> {
		crate::cli::init::host_secrets::acme::place(&self.config.data_dir, on)
	}

	fn write_compose(&mut self, text: &str) -> Result<(), String> {
		crate::storage::write_secret(self.compose, text.as_bytes())
			.map_err(|error| format!("cannot write {}: {error}", self.compose.display()))
	}

	fn podup(&mut self, step: &[&str]) -> Result<(), String> {
		if crate::cli::stack::run_sequence(self.podup, self.compose, &[step]) == ExitCode::SUCCESS {
			Ok(())
		} else {
			Err(format!("`podup {}` failed", step.join(" ")))
		}
	}

	fn wait_ready(&mut self, service: &str) -> Result<(), String> {
		crate::cli::stack::health::wait_healthy(self.podup, self.compose, service, READY_TIMEOUT)
	}

	fn retire_data_dir_key(&mut self) -> Result<Option<String>, String> {
		crate::cli::init::host_secrets::acme::retire_data_dir_copy(&self.config.data_dir)
	}

	fn log(&mut self, line: &str) {
		let _ = writeln!(crate::cli::style::stderr(), "epistle: {line}");
	}
}

/// Turn the certificates container `on` or off for the stack at `compose`,
/// as the service account.
pub(in crate::cli) fn run(config: &Config, compose: &Path, podup: &str, on: bool) -> ExitCode {
	let mut host = StackHost {
		config,
		compose,
		podup,
	};
	let state = if on { "on" } else { "off" };
	match switch(&mut host, on) {
		Ok(Switched::Done) => {
			host.log(&format!("the certificates container is {state}"));
			ExitCode::SUCCESS
		}
		Ok(Switched::AlreadyThere) => {
			host.log(&format!("the certificates container was already {state}"));
			ExitCode::SUCCESS
		}
		Err(error) => {
			crate::cli::style::error(format_args!("stack certs: {error}"));
			ExitCode::FAILURE
		}
	}
}
