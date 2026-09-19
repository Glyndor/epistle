//! The `epistle local` subcommand: a self-contained server on loopback.
//!
//! This is the test harness that lets every other feature be exercised
//! without a domain, DNS records or certificates. It binds six listeners
//! on `127.0.0.1`, holds outbound delivery so nothing leaves the host,
//! and creates a complete working directory the first time it runs. On a
//! later run it REUSES that directory byte for byte (idempotence).

mod config;
mod layout;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::config::{Config, ListenerKind};

/// Hard-coded identity: `.test` is reserved by RFC 6761 and never resolves,
/// so nothing here can accidentally reach a real zone.
pub const HOSTNAME: &str = "mail.local.test";

/// The single domain this server accepts mail for.
pub const DOMAIN: &str = "local.test";

/// The single account name this server ships with.
pub const ACCOUNT_NAME: &str = "user";

/// Marker file that signals "this directory was created by `epistle local`".
pub const MARKER_FILE: &str = ".epistle-local";

/// Default port offset (`--port-base`) when the operator does not set one.
pub const DEFAULT_PORT_BASE: u16 = 10000;

/// Errors produced while preparing a local-mode directory. Each variant
/// owns its diagnostic so a caller can `style::error` it without an
/// intermediate formatting step, and so a taint analyser reading a
/// constant string into the diagnostic stream cannot pretend the
/// constant is a credential.
#[derive(Debug)]
pub(super) enum LocalError {
	/// `--port-base` is outside `1024..=65535` once an offset is applied.
	/// Carries the port (as a `u32`, since an over-large `port_base` can
	/// compute a port that no longer fits in `u16`) that fell outside the
	/// allowed range, so the operator can see at a glance which offset is
	/// the problem.
	PortOutOfRange(u32),
	/// The system CSPRNG could not produce bytes (fail closed).
	CsprngUnavailable,
	/// Generating the DKIM key with the same path `dkim-keygen` uses failed.
	DkimKey(String),
	/// Writing the self-signed certificate failed.
	Certificate(String),
	/// Adding the default account via the same code `account-add` uses
	/// failed (e.g. the account already exists).
	Account(String),
	/// Refusing to write into a directory that holds an unrelated file and
	/// was not created by `epistle local`.
	NotEmpty(PathBuf),
	/// Some other I/O failure while preparing the directory tree.
	Io(std::io::Error),
}

impl std::fmt::Display for LocalError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			LocalError::PortOutOfRange(port) => write!(
				f,
				"--port-base puts listener port {port} outside 1024..=65535; \
                 pick a smaller base"
			),
			LocalError::CsprngUnavailable => f.write_str("system CSPRNG unavailable"),
			LocalError::DkimKey(why) => write!(f, "cannot generate DKIM key: {why}"),
			LocalError::Certificate(why) => write!(f, "cannot generate certificate: {why}"),
			LocalError::Account(why) => write!(f, "cannot create default account: {why}"),
			LocalError::NotEmpty(path) => write!(
				f,
				"{} is not empty and was not created by \"epistle local\"",
				path.display()
			),
			LocalError::Io(error) => write!(f, "{error}"),
		}
	}
}

impl From<std::io::Error> for LocalError {
	fn from(error: std::io::Error) -> Self {
		LocalError::Io(error)
	}
}

/// Outcome of preparing a local-mode directory. Drives the on-screen banner:
/// the password is printed once and only on the run that generated it, so
/// the operator's notes can carry it; the same directory reused on a later
/// run carries the same hash, so the password never leaves memory twice.
pub(super) struct Prepared {
	/// The configuration that was generated (or re-loaded from the marker
	/// directory). `hold_outbound` is always `true`.
	pub config: Config,
	/// Account name (`user`), so the banner can echo it back.
	pub account: String,
	/// The plaintext password: only set when the run actually generated it.
	/// Idempotent reuse leaves this `None` so the operator is not led to
	/// believe the system just minted a new password.
	pub password: Option<String>,
}

/// Manual `Debug` so a panic that prints the struct does not dump the
/// plaintext password into the test log. The same rule `Config`'s own
/// `Debug` follows for `srs_secret`.
impl std::fmt::Debug for Prepared {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Prepared")
			.field("config", &self.config)
			.field("account", &self.account)
			.field("password", &self.password.as_ref().map(|_| "<redacted>"))
			.finish()
	}
}

/// Prepare the directory at `dir`, generating (or reusing) every artifact
/// `epistle local` needs and returning the matching `Config`. The function
/// is split out from `run` so unit tests can drive every layout / permission
/// / idempotence pin without ever binding a listener.
///
/// Recovery from an interruption: each artifact is now skipped when its
/// file already exists on disk. The credential pair (`mail.toml` plus
/// `accounts.toml`) is regenerated together when either half is missing,
/// because the API token hash inside `mail.toml` and the account password
/// hash inside `accounts.toml` carry independent secrets and a partial
/// state where only one half survived is not useful.
pub(super) fn prepare(dir: &Path, port_base: u16) -> Result<Prepared, LocalError> {
	config::check_port_base(port_base)?;
	let _ = layout::ensure_dir(dir)?;
	let data_dir = dir.join("data");
	layout::create_with_mode(&data_dir, 0o700)?;

	let cert_path = dir.join("cert.pem");
	let key_path = dir.join("key.pem");
	let dkim_path = dir.join("dkim.pem");
	let mail_toml_path = dir.join("mail.toml");
	let accounts_toml_path = data_dir.join("accounts.toml");
	let marker_path = dir.join(MARKER_FILE);

	let mut password = None;

	// Cert and key are paired: TLS material needs both, and a partial
	// write that left only one is not loadable. Regenerating the pair is
	// cheap, so the rule is "any missing piece regenerates the pair".
	if !cert_path.exists() || !key_path.exists() {
		std::fs::remove_file(&cert_path).ok();
		std::fs::remove_file(&key_path).ok();
		layout::generate_certificate(&cert_path, &key_path)?;
	}

	// DKIM key is independent; treat it like the certificate.
	if !dkim_path.exists() {
		std::fs::remove_file(&dkim_path).ok();
		layout::write_dkim_key(&dkim_path)?;
	}

	// The credential pair. Either file present and valid is enough to
	// reuse both; if either is missing, regenerate both with fresh
	// secrets so they stay consistent with each other. An existing
	// `mail.toml` that fails to parse is treated as missing for the
	// same reason (next run would refuse to start anyway).
	let mail_valid = mail_toml_path.exists() && config::load_local_config(&mail_toml_path).is_ok();
	let accounts_present = accounts_toml_path.exists();
	if !mail_valid || !accounts_present {
		let api_token_hash = layout::generate_api_token_hash()?;
		let pwd = layout::generate_account_password()?;
		config::write_mail_toml_replace(
			dir,
			port_base,
			&cert_path,
			&key_path,
			&dkim_path,
			&api_token_hash,
		)?;
		let account = crate::directory_store::DynamicAccount::with_password(
			ACCOUNT_NAME.to_string(),
			vec![format!("{ACCOUNT_NAME}@{DOMAIN}")],
			&pwd,
		)
		.map_err(|error| LocalError::Account(error.to_string()))?;
		layout::write_account_replace(&accounts_toml_path, &account)?;
		password = Some(pwd);
	}

	// Marker is the trust anchor. Written last so a directory that
	// holds unrelated files but no marker is still refused.
	if !marker_path.exists() {
		layout::write_marker(&marker_path)?;
	}

	let config = config::load_local_config(&mail_toml_path)?;

	Ok(Prepared {
		config,
		account: ACCOUNT_NAME.to_string(),
		password,
	})
}

/// Run `epistle local` end to end: prepare the directory, print the banner,
/// then hand off to the same `serve::run` `epistle serve` uses, with the
/// generated in-memory config. The banner uses `starting` rather than
/// `ready`: `serve` has no hook that fires after binding, so any "ready"
/// printed before `serve::run` returned would be a lie the operator
/// catches the first time a listener fails to bind.
pub(super) fn run(dir: PathBuf, port_base: u16) -> ExitCode {
	let prepared = match prepare(&dir, port_base) {
		Ok(prepared) => prepared,
		Err(error) => {
			super::style::error(error);
			return ExitCode::FAILURE;
		}
	};
	let endpoints: Vec<(ListenerKind, u16)> = config::LISTENERS
		.iter()
		.map(|(kind, offset)| (*kind, port_base + offset))
		.collect();
	// The banner goes to stderr. stdout is reserved for command data on
	// every command in this binary, and `epistle local` produces none, so
	// stdout stays empty. The test in `local_tests.rs` pins both halves:
	// the writer handed in is `style::stderr()`, and there is no `println!`
	// anywhere in `local/`.
	print_banner(
		&dir,
		&endpoints,
		&prepared.account,
		prepared.password.as_deref(),
		&mut super::style::stderr(),
	);
	super::serve::run(prepared.config)
}

/// Print the on-start banner to `out`. The password is only printed on
/// the run that generated it; the operator is told it will not be shown
/// again so they do not expect a repeat on a second `epistle local`.
///
/// The first line says `starting`, not `ready`: `serve` prints nothing
/// the operator can hook into between binding and the first failure, so
/// the word would either be a lie (printed before binding) or require
/// restructuring `serve` to add a callback. The latter is a `serve`
/// change this branch explicitly does not make.
///
/// The writer is taken as `&mut impl Write` so the test passes a
/// `Vec<u8>` and asserts the bytes the operator would see on stderr.
pub(super) fn print_banner(
	dir: &Path,
	endpoints: &[(ListenerKind, u16)],
	account: &str,
	password: Option<&str>,
	out: &mut impl Write,
) {
	let _ = writeln!(out, "epistle local: starting");
	let _ = writeln!(out, "  directory: {}", dir.display());
	for (kind, port) in endpoints {
		let _ = writeln!(
			out,
			"  listening: 127.0.0.1:{port} ({})",
			config::kind_name(*kind)
		);
	}
	let _ = writeln!(out, "  account:   {account}@{DOMAIN}");
	match password {
		Some(pwd) => {
			let _ = writeln!(out, "  password:  {pwd}  (shown once, not stored)");
		}
		None => {
			let _ = writeln!(out, "  password:  (reused from this directory, not shown)");
		}
	}
}

#[cfg(test)]
#[path = "test_support.rs"]
mod test_support;

#[cfg(test)]
#[path = "layout_tests.rs"]
mod layout_tests;

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;

#[cfg(test)]
#[path = "local_tests.rs"]
mod tests;
