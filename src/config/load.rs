//! Reading the configuration file from disk, and the decisions that read the
//! loaded values.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use super::permissions::check_permissions;
use super::{Config, ConfigError, Webhook};

impl Config {
	/// Load and validate a configuration file. Fails closed: insecure
	/// permissions, a read, parse or validation error, or an undefined
	/// referenced environment variable all abort loading.
	///
	/// Secrets should not be written into the file directly: any `${VAR}` in
	/// the file is substituted from the process environment at load time, so
	/// credentials (e.g. the database password) can stay in the environment or
	/// a secret store rather than on disk.
	pub fn load(path: &Path) -> Result<Self, ConfigError> {
		check_permissions(path, "config file")?;
		let raw = super::read::text(path)?;
		Self::parse_text(&raw, path)
	}

	/// [`load`](Self::load) with the named top-level tables taken out before
	/// the file is parsed and validated, for a process that never uses them
	/// and does not mount the files their validation reads: the
	/// certificates container has no `[database]` password file. Every other
	/// rule applies as in `load`; a file that does not parse as TOML fails
	/// the same way.
	pub(crate) fn load_without(path: &Path, tables: &[&str]) -> Result<Self, ConfigError> {
		check_permissions(path, "config file")?;
		let raw = super::read::text(path)?;
		let text = match raw.parse::<toml_edit::DocumentMut>() {
			Ok(mut document) => {
				for table in tables {
					document.remove(table);
				}
				document.to_string()
			}
			Err(_) => raw,
		};
		Self::parse_text(&text, path)
	}

	/// [`load`](Self::load) for `epistle status` alone: it reports on an
	/// installation, so a file the validation refuses is still read and the
	/// reason is kept in [`Config::validation_error`] for the `config` area.
	/// Every command that acts on the data (`backup`, `restore`, `stack
	/// rollback`, `serve`) uses `load` and refuses such a file, because the
	/// rules it breaks can be the ones that keep a dump off an unprotected
	/// connection or a path inside the data directory. A file that cannot be
	/// read or parsed still fails here.
	pub(crate) fn load_lenient(path: &Path) -> Result<Self, ConfigError> {
		check_permissions(path, "config file")?;
		let raw = super::read::text(path)?;
		Self::parse_text_lenient(&raw, path)
	}

	/// The `[webhook]` section when it is there and switched on. Whatever
	/// posts an event reads the section through this, so a webhook with
	/// `enabled = false` posts nothing.
	pub fn active_webhook(&self) -> Option<&Webhook> {
		self.webhook.as_ref().filter(|webhook| webhook.enabled)
	}

	/// The hosted domains that are switched on: `domains` without
	/// `disabled_domains`.
	pub fn enabled_domains(&self) -> Vec<String> {
		self.domains
			.iter()
			.filter(|domain| {
				!self
					.disabled_domains
					.iter()
					.any(|disabled| disabled.eq_ignore_ascii_case(domain))
			})
			.cloned()
			.collect()
	}

	/// The loopback address listeners bind to unless explicitly configured.
	pub const fn default_bind_addr() -> IpAddr {
		IpAddr::V4(Ipv4Addr::LOCALHOST)
	}

	/// Whether the outbound queue worker should be started for this config.
	/// `false` only when `hold_outbound` is `true`, a flag `epistle local`
	/// sets to keep the harness from opening any outbound SMTP connection.
	/// Pulled out so the `serve` startup path and the unit tests share the
	/// same source of truth.
	pub fn start_queue_worker(&self) -> bool {
		!self.hold_outbound
	}
}
