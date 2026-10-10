//! Building the in-memory `Config` and the port offset table. The six
//! listener offsets are the single source of truth: `check_port_base` and
//! `write_mail_toml` cannot drift on which listener gets which offset
//! because both consult the same `LISTENERS` table.

use std::path::Path;

use crate::config::{Config, ListenerKind};

use super::{ACCOUNT_NAME, DOMAIN, HOSTNAME};

/// Each listener kind and its port offset from `--port-base`. The contract
/// pins the six endpoints: SMTP, submission, submissions, IMAP, IMAPS, API.
pub(super) const LISTENERS: &[(ListenerKind, u16)] = &[
	(ListenerKind::Smtp, 25),
	(ListenerKind::Submission, 587),
	(ListenerKind::Submissions, 465),
	(ListenerKind::Imap, 143),
	(ListenerKind::Imaps, 993),
	(ListenerKind::Api, 8025),
];

/// Human-readable listener kind name for the banner. Mirrors the kebab-case
/// spelling the operator sees in `mail.toml`, so the on-screen output is
/// recognisably the same protocol the config names.
pub(super) fn kind_name(kind: ListenerKind) -> &'static str {
	match kind {
		ListenerKind::Smtp => "smtp",
		ListenerKind::Submission => "submission",
		ListenerKind::Submissions => "submissions",
		ListenerKind::Imap => "imap",
		ListenerKind::Imaps => "imaps",
		ListenerKind::Api => "api",
		ListenerKind::Pop3s => "pop3s",
		ListenerKind::ManageSieve => "managesieve",
		ListenerKind::Metrics => "metrics",
		ListenerKind::Acme => "acme",
		ListenerKind::Autoconfig => "autoconfig",
		ListenerKind::WebDav => "webdav",
	}
}

/// Validate that every listener port falls in `1024..=65535`. Returns the
/// first port that is outside the range so the operator can fix the offset
/// without reading the whole list. The port is carried as a `u32` so a
/// computed port larger than `u16::MAX` still names the offending value.
pub(super) fn check_port_base(port_base: u16) -> Result<(), super::LocalError> {
	for (_, offset) in LISTENERS {
		let port = u32::from(port_base) + u32::from(*offset);
		if !(1024..=65535).contains(&port) {
			return Err(super::LocalError::PortOutOfRange(port));
		}
	}
	Ok(())
}

/// Render the `mail.toml` that `epistle config-check` accepts. Built in
/// memory and emitted through `Display` so the on-disk layout exactly
/// matches the format `toml::to_string` would produce for the same data.
///
/// `dir` is the harness base directory; the file is written to
/// `<dir>/mail.toml` and the `data_dir` it references is `<dir>/data`. The
/// previous iteration passed the future `mail.toml` path as `dir` and
/// computed `path.join("data")`, which produced
/// `data_dir = "<dir>/mail.toml/data"`, a path inside a regular file.
/// `serve` then tried to create the spool under that path and
/// `FsSpool::open_with_crypto` failed with
/// `Not a directory (os error 20)` on the first `create_dir_all`. The
/// function takes `dir` (not the file path) so the same `dir.join("data")`
/// the layout module uses for the directory the spool lives in is the
/// path the config names.
pub(super) fn write_mail_toml_replace(
	dir: &Path,
	port_base: u16,
	cert_file: &Path,
	key_file: &Path,
	dkim_file: &Path,
	api_token_hash: &str,
) -> Result<(), super::LocalError> {
	let listeners: Vec<String> = LISTENERS
		.iter()
		.map(|(kind, offset)| {
			format!(
				"[[listeners]]\nkind = \"{}\"\naddr = \"127.0.0.1\"\nport = {}\n",
				listener_kind_toml(*kind),
				port_base + offset
			)
		})
		.collect();
	let body = format!(
		"hostname = \"{HOSTNAME}\"\n\
         data_dir = {}\n\
         domains = [\"{DOMAIN}\"]\n\
         greylist_delay_secs = 0\n\
         dnsbl_zones = []\n\
         dnsbl_domain_zones = []\n\
         dnsbl_url_zones = []\n\
         first_time_sender_delay_secs = 0\n\
         masked_addresses_max = 0\n\
         {}\n\
         [tls]\n\
         cert_file = {}\n\
         key_file = {}\n\
         [dkim]\n\
         selector = \"epistle-local\"\n\
         key_file = {}\n\
         [api]\n\
         token_hash = \"{}\"\n\
         admins = [\"{ACCOUNT_NAME}\"]\n",
		toml_path(&dir.join("data")),
		listeners.join("\n"),
		toml_path(cert_file),
		toml_path(key_file),
		toml_path(dkim_file),
		api_token_hash,
	);
	super::layout::write_with_replace(&dir.join("mail.toml"), body.as_bytes(), 0o600)
}

// TOML string values escape quotes, backslashes and control characters in paths.
fn toml_path(path: &Path) -> toml::Value {
	toml::Value::String(path.to_string_lossy().into_owned())
}

/// The kebab-case spelling of a listener kind for the config file.
fn listener_kind_toml(kind: ListenerKind) -> &'static str {
	match kind {
		ListenerKind::Smtp => "smtp",
		ListenerKind::Submission => "submission",
		ListenerKind::Submissions => "submissions",
		ListenerKind::Imap => "imap",
		ListenerKind::Imaps => "imaps",
		ListenerKind::Api => "api",
		ListenerKind::Pop3s => "pop3s",
		ListenerKind::ManageSieve => "managesieve",
		ListenerKind::Metrics => "metrics",
		ListenerKind::Acme => "acme",
		ListenerKind::Autoconfig => "autoconfig",
		ListenerKind::WebDav => "webdav",
	}
}

/// Outcome of loading a `mail.toml` through the production parser.
/// `prepare` uses the three-state split: a missing file means
/// "regenerate", a usable file means "reuse the pair", and any file
/// that is present but cannot be used as-is means "propagate as an
/// error" (a parse failure, a missing env var, a validation failure, a
/// read failure, an insecure-permission rejection are all the same
/// shape: the file is on disk, the operator can fix the underlying
/// condition, and silently regenerating would replace credentials
/// behind the operator's back).
#[derive(Debug)]
pub(super) enum MailConfigOutcome {
	/// The file does not exist on disk. `prepare` regenerates the pair.
	Missing,
	/// The file exists and parsed through `Config::load`. `prepare`
	/// reuses the pair.
	Loaded(Box<Config>),
	/// The file is present but unusable for any reason: read error,
	/// insecure permissions, parse failure, missing env var,
	/// validation failure. The string is the operator-facing
	/// diagnostic (path + cause + remedy). `prepare` returns this
	/// error and does not touch the credential files.
	Unusable(String),
}

/// Outcome of loading the dynamic `accounts.toml` through the same
/// production loader `serve` uses. The three states mirror the
/// `mail.toml` outcome: a missing file means "regenerate", a usable
/// file means "reuse", and any failure (the `accounts.toml` parse, an
/// `app_passwords.toml` or `masked.json` sidecar failing to open, the
/// expected account being absent from a store that opened) means
/// "propagate as an error".
#[derive(Debug)]
pub(super) enum AccountsOutcome {
	/// The file does not exist on disk. `prepare` regenerates the pair.
	Missing,
	/// The file exists, parses, the store opened cleanly, and the
	/// expected account is present. `prepare` reuses the pair.
	Loaded,
	/// The file is present but the store cannot be used as-is: the
	/// accounts.toml parse failed, a sidecar file (app_passwords.toml
	/// or masked.json) failed to read or parse, or the expected
	/// account is absent. The string is the operator-facing
	/// diagnostic (data dir + cause + remedy). `prepare` returns this
	/// error and does not touch the credential files.
	Unusable(String),
}

/// Load the just-written `mail.toml` back through the production parser so
/// `Config::validate` runs over what the harness generated. `hold_outbound`
/// is set programmatically afterwards so the loader never sees it.
pub(super) fn load_local_config(path: &Path) -> Result<Config, super::LocalError> {
	match load_local_config_outcome(path)? {
		MailConfigOutcome::Loaded(config) => Ok(*config),
		MailConfigOutcome::Missing => Err(super::LocalError::Io(std::io::Error::other(
			diagnostic_missing(&path.display().to_string()),
		))),
		MailConfigOutcome::Unusable(diagnostic) => {
			Err(super::LocalError::Io(std::io::Error::other(diagnostic)))
		}
	}
}

/// Build the `Missing` diagnostic. Carries the path so the operator sees
/// which file was absent and the same remedy hint the `Unusable` arm
/// produces, so the two error shapes look alike to the operator even
/// though `prepare` is the only path that ever surfaces a true missing
/// file (the helper exists for the `load_local_config` direct-call
/// path).
fn diagnostic_missing(path: &str) -> String {
	format!(
		"{path}: mail.toml is absent. Fix it, or remove {path} to start over with fresh credentials."
	)
}

/// Build the standard `Unusable` diagnostic from a path and a cause. The
/// shape is fixed because both `prepare` and `load_local_config` return
/// it to the operator: `<path>: <cause>. Fix it, or remove <path> to
/// start over with fresh credentials.` The remedy names the path
/// itself, not any subset of the directory, because a sidecar failure
/// in `data/` only goes away if the whole directory is removed; a
/// half-measure that kept `mail.toml` while rewriting `accounts.toml`
/// would rotate the credential pair behind the operator's back.
pub(super) fn unusable_diagnostic(path: &str, cause: &str) -> String {
	format!("{path}: {cause}. Fix it, or remove {path} to start over with fresh credentials.")
}

/// Load `mail.toml` and split the result into the three states `prepare`
/// needs to make the right decision. The "cannot be read" check runs
/// before `Config::load` because `check_permissions` rejects a directory
/// at the path as `InsecurePermissions` (the umask-created mode 0o755
/// has the world-readable bit set), and the operator must see that as
/// "the file on disk is not a file" rather than as "the config is
/// world-readable and must be regenerated". `read_to_string` on the
/// path is the only call the kernel refuses for every uid: a directory
/// yields `EISDIR`, a missing file yields `NotFound` (handled above),
/// a regular file with the right mode passes through to `Config::load`.
///
/// Every `ConfigError` variant `Config::load` produces is operator-fixable
/// on an otherwise-present file (read error, insecure permissions,
/// parse failure, missing env var, validation failure), so they all
/// collapse into [`MailConfigOutcome::Unusable`] with the standard
/// diagnostic. `prepare` propagates that as an error and does not touch
/// the credential files; regenerating would silently replace working
/// credentials behind the operator's back.
pub(super) fn load_local_config_outcome(
	path: &Path,
) -> Result<MailConfigOutcome, super::LocalError> {
	// `Path::try_exists` distinguishes "the file is absent" (Ok(false))
	// from "the kernel could not answer" (Err(_)). `Path::exists()` would
	// silently fold the second into the first, and any path that ends
	// up `Unusable`-shaped would be mis-classified as `Missing` and the
	// credential pair would be silently regenerated.
	match path.try_exists() {
		Ok(false) => return Ok(MailConfigOutcome::Missing),
		Ok(true) => {}
		Err(error) => {
			return Ok(MailConfigOutcome::Unusable(unusable_diagnostic(
				&path.display().to_string(),
				&format!("cannot stat: {error}"),
			)));
		}
	}
	if let Err(error) = std::fs::read_to_string(path) {
		if error.kind() == std::io::ErrorKind::NotFound {
			return Ok(MailConfigOutcome::Missing);
		}
		return Ok(MailConfigOutcome::Unusable(unusable_diagnostic(
			&path.display().to_string(),
			&format!("{error}"),
		)));
	}
	let mut config = match Config::load(path) {
		Ok(config) => config,
		Err(error) => {
			return Ok(MailConfigOutcome::Unusable(unusable_diagnostic(
				&path.display().to_string(),
				&format!("{error}"),
			)));
		}
	};
	config.hold_outbound = true;
	if config.start_queue_worker() {
		return Err(super::LocalError::Io(std::io::Error::other(
			"hold_outbound did not take effect after load",
		)));
	}
	Ok(MailConfigOutcome::Loaded(Box::new(config)))
}

/// Load `<data_dir>/accounts.toml` through the same production loader
/// `serve` uses, splitting the result into the three states `prepare`
/// needs. The loader is `AccountStore::open`, which calls
/// `read_to_string` on the same path the runtime walks and surfaces a
/// `StoreError` for any failure (parse, sidecar read, sidecar parse).
/// Every failure mode is operator-fixable on an otherwise-present data
/// directory (malformed TOML, a hand-truncated `masked.json`, the
/// harness's expected account being deleted from a file the store still
/// opened), so they all collapse into [`AccountsOutcome::Unusable`]
/// with the standard diagnostic. The cause is the store's own text
/// (`StoreError` `Display`); the operator sees the data directory plus
/// the loader's view of what failed, plus the single remedy: remove
/// the directory. `prepare` propagates the error and does not touch
/// the credential files.
///
/// `prepare` calls this BEFORE creating the data directory, so a
/// fresh directory state must read as `Missing`, not as an
/// `Unusable` "cannot stat accounts.toml" error. A missing data
/// directory implies a missing `accounts.toml`; the credential pair
/// is regenerated, which is what the data directory creation step
/// was about to do anyway.
pub(super) fn load_accounts_outcome(data_dir: &Path) -> Result<AccountsOutcome, super::LocalError> {
	match data_dir.try_exists() {
		Ok(false) => return Ok(AccountsOutcome::Missing),
		Ok(true) => {}
		Err(error) => {
			return Ok(AccountsOutcome::Unusable(unusable_accounts_diagnostic(
				data_dir,
				&format!("cannot stat data directory: {error}"),
			)));
		}
	}
	let path = data_dir.join("accounts.toml");
	// `Path::try_exists` distinguishes "the file is absent" (Ok(false))
	// from "the kernel could not answer" (Err(_)). `Path::exists()` would
	// silently fold the second into the first, and a data directory
	// whose `accounts.toml` cannot be stat'ed (e.g. when `data` itself
	// is a regular file) would be mis-classified as `Missing` and the
	// credential pair would be silently regenerated.
	match path.try_exists() {
		Ok(false) => return Ok(AccountsOutcome::Missing),
		Ok(true) => {}
		Err(error) => {
			return Ok(AccountsOutcome::Unusable(unusable_accounts_diagnostic(
				data_dir,
				&format!("cannot stat accounts.toml: {error}"),
			)));
		}
	}
	let store = match crate::directory_store::AccountStore::open(
		data_dir,
		Vec::new(),
		std::collections::HashMap::new(),
		Vec::new(),
	) {
		Ok(store) => store,
		Err(error) => {
			// The store's own text is the cause. Re-parsing the sidecars
			// here to "name" the failing file would shadow the
			// production loader's view: the sidecar schemas are
			// different from the production parser's (the production
			// `accounts.toml` deserialises into a typed `DynamicFile`,
			// not a bare `toml::Table`), and the substituted error
			// could blame a different file or a different line. The
			// data-directory path is the operator's pointer to "the
			// store under this directory is broken"; the underlying
			// `StoreError` text is the loader's view of why. The
			// standard remedy is to remove the directory; a partial
			// fix-up of a single file is not always possible because
			// the broken file may be a sidecar that the next run
			// regenerates against the regenerated accounts.
			return Ok(AccountsOutcome::Unusable(unusable_accounts_diagnostic(
				data_dir,
				&error.to_string(),
			)));
		}
	};
	if store
		.handle()
		.current()
		.credentials(super::ACCOUNT_NAME)
		.is_some()
	{
		Ok(AccountsOutcome::Loaded)
	} else {
		Ok(AccountsOutcome::Unusable(unusable_accounts_diagnostic(
			data_dir,
			&format!("required account {ACCOUNT_NAME:?} not found in accounts.toml"),
		)))
	}
}

/// Build the standard `AccountsOutcome::Unusable` diagnostic. The
/// `<dir>` named is the data directory because the store is opened
/// against the directory; the underlying `StoreError` text is the
/// cause so the operator sees the loader's view of the failure. The
/// remedy is to remove the directory.
fn unusable_accounts_diagnostic(data_dir: &Path, cause: &str) -> String {
	let dir = data_dir.display().to_string();
	format!("{dir}: {cause}. Fix it, or remove {dir} to start over with fresh credentials.")
}

#[cfg(test)]
#[path = "config_tests_paths.rs"]
mod tests_paths;
