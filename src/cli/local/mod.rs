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
/// Recovery from an interruption: each artifact is skipped when its file
/// already exists on disk. The credential pair (`mail.toml` plus
/// `accounts.toml`) is regenerated together when either half is missing,
/// because the API token hash inside `mail.toml` and the account password
/// hash inside `accounts.toml` carry independent secrets and a partial
/// state where only one half survived is not useful.
pub(super) fn prepare(dir: &Path, port_base: u16) -> Result<Prepared, LocalError> {
	config::check_port_base(port_base)?;
	layout::ensure_dir(dir)?;
	// Marker is the trust anchor and is written first, immediately after
	// `ensure_dir` accepts the directory. Writing it before any other
	// artifact means a crash later in the run still leaves a directory a
	// later run sees as ours: the marker is present, so `ensure_dir`
	// accepts the directory, and the per-artifact scan below rebuilds
	// whatever else is missing. Writing the marker last would mean a
	// crash between the first artifact and the marker left a directory
	// `ensure_dir` then refused as "not empty and was not created by
	// epistle local", which is exactly the partial state this function
	// exists to recover from.
	layout::write_marker(&dir.join(MARKER_FILE))?;

	// Test-only fault point: a synthetic failure `prepare` can be
	// driven into to prove the marker is written before any other
	// artifact, including before the data directory is created. The
	// call is placed AFTER `write_marker` (so a successful arming
	// leaves the marker on disk) and BEFORE the data directory or any
	// artifact (so neither the data directory nor any artifact is on
	// disk when the fault fires). Together those pin the
	// marker-first ordering invariant of `prepare`. Outside tests the
	// function is a no-op returning `Ok(())`, so the production path
	// is unaffected.
	layout::fault_after_marker()?;

	let data_dir = dir.join("data");
	let cert_path = dir.join("cert.pem");
	let key_path = dir.join("key.pem");
	let dkim_path = dir.join("dkim.pem");
	let mail_toml_path = dir.join("mail.toml");
	let accounts_toml_path = data_dir.join("accounts.toml");

	// Decide the credential-pair outcome BEFORE creating the data
	// directory, regenerating the certificate, or writing the DKIM
	// key. A `mail.toml` or `accounts.toml` that is on disk but
	// unusable is an operator-fixable error; an error run that
	// regenerated the cert/key/dkim in the meantime would leave the
	// directory in a half-changed state (fresh cert/key, broken
	// `mail.toml`) that a fix-up run could not recognise. The
	// evaluation is read-only: the data directory does not have to
	// exist for `load_accounts_outcome` to return a `Missing` outcome
	// (a fresh directory implies a fresh credential pair), and the
	// `Unusable` arm carries the standard diagnostic. Once the
	// outcome is decided, the rest of the run is a no-op when the
	// pair is reusable, and an artifact-creation pass when it is not.
	let mail_outcome = config::load_local_config_outcome(&mail_toml_path)?;
	let accounts_outcome = config::load_accounts_outcome(&data_dir)?;
	let pair_usable = matches!(
		(&mail_outcome, &accounts_outcome),
		(
			config::MailConfigOutcome::Loaded(_),
			config::AccountsOutcome::Loaded
		)
	);
	if !pair_usable {
		match mail_outcome {
			config::MailConfigOutcome::Unusable(diagnostic) => {
				return Err(LocalError::Io(std::io::Error::other(diagnostic)));
			}
			config::MailConfigOutcome::Missing | config::MailConfigOutcome::Loaded(_) => {}
		}
		match accounts_outcome {
			config::AccountsOutcome::Unusable(diagnostic) => {
				return Err(LocalError::Io(std::io::Error::other(diagnostic)));
			}
			config::AccountsOutcome::Missing | config::AccountsOutcome::Loaded => {}
		}
	}

	// Now it is safe to write the data directory and the other
	// artifacts. Each step is skipped if the file is already on disk
	// (and non-empty for the cert/key/dkim shape).
	layout::create_with_mode(&data_dir, 0o700)?;

	let mut password = None;

	// Cert and key are paired: TLS material needs both, and a partial
	// write that left only one is not loadable. A zero-length file is
	// treated as missing because a partial write or a hand-truncated
	// file can leave an empty `cert.pem` / `key.pem` on disk; the
	// runtime would refuse to load it. Regenerating the pair is cheap,
	// so the rule is "any missing or empty piece regenerates the pair".
	if !layout::is_nonempty_file(&cert_path) || !layout::is_nonempty_file(&key_path) {
		let _ = std::fs::remove_file(&cert_path);
		let _ = std::fs::remove_file(&key_path);
		layout::generate_certificate(&cert_path, &key_path)?;
	}

	// DKIM key is independent; treat it like the certificate. Same
	// zero-length rule for the same reason.
	if !layout::is_nonempty_file(&dkim_path) {
		let _ = std::fs::remove_file(&dkim_path);
		layout::write_dkim_key(&dkim_path)?;
	}

	// Regenerate the credential pair only when at least one half is
	// missing. Both files are rewritten together because the API
	// token hash inside `mail.toml` and the account password hash
	// inside `accounts.toml` are independent secrets; a partial
	// state where only one half was rewritten is not loadable.
	let config = if !pair_usable {
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
		// Reload to pick up the just-written `mail.toml`; the early
		// `Loaded(_)` shape is the on-disk file from a previous run
		// and we just overwrote it.
		config::load_local_config(&mail_toml_path)?
	} else {
		match mail_outcome {
			config::MailConfigOutcome::Loaded(config) => *config,
			// `pair_usable` requires `mail_outcome` to be `Loaded`;
			// the only way to reach this arm otherwise is a logic
			// error in the matches! above, which the test in
			// `idempotence_second_run_reuses_every_generated_file`
			// already exercises.
			config::MailConfigOutcome::Missing | config::MailConfigOutcome::Unusable(_) => {
				unreachable!()
			}
		}
	};

	Ok(Prepared {
		config,
		account: ACCOUNT_NAME.to_string(),
		password,
	})
}

/// Build the `(kind, port)` list the banner prints, derived from the
/// already-loaded `Config`. Reading the listeners (rather than the
/// requested `--port-base`) is what guarantees the banner matches what
/// `serve` will bind, including when an operator restarts a directory
/// that was prepared earlier with a different base.
pub(super) fn banner_endpoints(config: &Config) -> Vec<(ListenerKind, u16)> {
	config
		.listeners
		.iter()
		.map(|listener| {
			(
				listener.kind,
				listener
					.port
					.unwrap_or_else(|| listener.kind.default_port()),
			)
		})
		.collect()
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
	let endpoints = banner_endpoints(&prepared.config);
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
#[path = "layout_key_tests.rs"]
mod layout_key_tests;

#[cfg(test)]
#[path = "layout_recovery_tests.rs"]
mod layout_recovery_tests;

#[cfg(test)]
#[path = "layout_storage_tests.rs"]
mod layout_storage_tests;

#[cfg(test)]
#[path = "layout_replace_tests.rs"]
mod layout_replace_tests;

#[cfg(test)]
#[path = "config_accounts_tests.rs"]
mod config_accounts_tests;

#[cfg(test)]
#[path = "config_listener_tests.rs"]
mod config_listener_tests;

#[cfg(test)]
#[path = "config_mail_tests.rs"]
mod config_mail_tests;

#[cfg(test)]
#[path = "local_tests.rs"]
mod tests;
