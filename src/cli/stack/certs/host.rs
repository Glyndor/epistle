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
	fn compose_path(&self) -> &Path {
		self.compose
	}

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
		crate::cli::stack::health::wait_healthy(self.podup, self.compose, service, READY_TIMEOUT)?;
		if service != "certs" {
			return Ok(());
		}
		// `certs` has no healthcheck, so "running" is all podup reports, and
		// a container that exits at start is running again a second later
		// under `restart: unless-stopped`. It is ready once it has kept the
		// same start for a while.
		let upness = super::upness(self.podup, self.compose, service, super::STEADY);
		if upness.is_up() {
			return Ok(());
		}
		Err(format!(
			"{}; `epistle stack logs {service}` says why",
			upness.why(service)
		))
	}

	fn retire_data_dir_key(&mut self) -> Result<Option<String>, String> {
		crate::cli::init::host_secrets::acme::retire_data_dir_copy(&self.config.data_dir)
	}

	fn data_dir_key(&self) -> std::path::PathBuf {
		crate::acme::renew::account_key_path(&self.config.data_dir)
	}

	fn log(&mut self, line: &str) {
		let _ = writeln!(crate::cli::style::stderr(), "epistle: {line}");
	}
}

/// Turn the certificates container `on` or off for the stack at `compose`,
/// as the service account, after checking that the configuration can renew
/// from `certs` and asking unless `yes`.
pub(in crate::cli) fn run(
	config: &Config,
	compose: &Path,
	podup: &str,
	on: bool,
	yes: bool,
) -> ExitCode {
	if on && let Err(reason) = preflight(config) {
		crate::cli::style::error(format_args!("stack certs enable: {reason}"));
		return ExitCode::FAILURE;
	}
	let (action, question) = if on {
		(
			"stack certs enable",
			"Move the ACME renewal, the TLSA refresh and the DNS credential into a certs \
			 container, and recreate mail without them? [y/N]",
		)
	} else {
		(
			"stack certs disable",
			"Put the ACME renewal and the DNS credential back in mail and remove the certs \
			 container? [y/N]",
		)
	};
	if let Err(code) = crate::cli::prompt::confirm_destructive(action, question, yes) {
		return code;
	}
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

/// What the stack needs before it is touched: a configuration the
/// certificates container can renew with, a DNS credential it can read and
/// an ACME account key that exists.
///
/// Each of the three is checked here, before the question and before the
/// stack is touched, because each of them stops the container at start:
/// after `mail` was stopped and the compose file rewritten, a container
/// that cannot renew is a failed switch and a stack that has to be put
/// back.
pub(in crate::cli) fn preflight(config: &Config) -> Result<(), String> {
	// The `[acme]` section the container renews with.
	let _acme = crate::cli::serve::certs_requirements(config)?;
	dns_credential(config)?;
	account_key(config)?;
	Ok(())
}

/// Whether the DNS credential the configuration names can be read: the
/// certificates container publishes the dns-01 challenge and the TLSA record
/// through it, and a credential it cannot read is a container that exits at
/// start.
fn dns_credential(config: &Config) -> Result<(), String> {
	let Some(dns) = config.dns.entry_for(&config.hostname) else {
		return Err(format!(
			"the [dns] configuration has no entry for {}, and the certificates container \
			 publishes the dns-01 challenge through it",
			config.hostname
		));
	};
	if dns.build_for_host(&config.hostname).is_none() {
		return Err(format!(
			"the [dns] credential for {} cannot be read (provider {:?}), and the certificates \
			 container publishes the dns-01 challenge and the TLSA record through it",
			dns.zone, dns.provider
		));
	}
	Ok(())
}

/// Whether an ACME account key exists: the certificates container reads it
/// from a mount it cannot write, and a key that is nowhere is a new account
/// with the authority, which the switch does not register behind the
/// operator's back.
fn account_key(config: &Config) -> Result<(), String> {
	if crate::cli::init::host_secrets::acme::account_key_survives(&config.data_dir)? {
		return Ok(());
	}
	Err(crate::cli::init::host_secrets::acme::no_account_key(
		&config.data_dir,
	))
}
