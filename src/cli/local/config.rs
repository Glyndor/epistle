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
pub(super) fn write_mail_toml(
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
         data_dir = \"{}\"\n\
         domains = [\"{DOMAIN}\"]\n\
         greylist_delay_secs = 0\n\
         dnsbl_zones = []\n\
         dnsbl_domain_zones = []\n\
         dnsbl_url_zones = []\n\
         first_time_sender_delay_secs = 0\n\
         masked_addresses_max = 0\n\
         {}\n\
         [tls]\n\
         cert_file = \"{}\"\n\
         key_file = \"{}\"\n\
         [dkim]\n\
         selector = \"epistle-local\"\n\
         key_file = \"{}\"\n\
         [api]\n\
         token_hash = \"{}\"\n\
         admins = [\"{ACCOUNT_NAME}\"]\n",
		dir.join("data").display(),
		listeners.join("\n"),
		cert_file.display(),
		key_file.display(),
		dkim_file.display(),
		api_token_hash,
	);
	super::layout::write_with_mode(&dir.join("mail.toml"), body.as_bytes(), 0o600)
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

/// Load the just-written `mail.toml` back through the production parser so
/// `Config::validate` runs over what the harness generated. `hold_outbound`
/// is set programmatically afterwards so the loader never sees it.
pub(super) fn load_local_config(path: &Path) -> Result<Config, super::LocalError> {
	let mut config = Config::load(path)
		.map_err(|error| super::LocalError::Io(std::io::Error::other(error.to_string())))?;
	config.hold_outbound = true;
	// Sanity: the loader must have rejected the field as unknown.
	if !config.start_queue_worker() {
		Ok(config)
	} else {
		Err(super::LocalError::Io(std::io::Error::other(
			"hold_outbound did not take effect after load",
		)))
	}
}
