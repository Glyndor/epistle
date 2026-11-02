//! Serialized setup configuration.

use serde::Serialize;
use std::net::IpAddr;

/// Build the desired `Config` value from the answers. Each listener
/// line carries its kind and an explicit `addr`; the operator-visible
/// default of `127.0.0.1` is no longer the answer for any listener
/// `init` writes, because loopback-only mail listeners receive no
/// mail and serve nobody.
#[derive(Debug, Serialize)]
pub(in crate::cli::init::apply) struct DesiredConfig {
	pub(in crate::cli::init::apply) hostname: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) public_ipv4: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) public_ipv6: Option<String>,
	pub(in crate::cli::init::apply) data_dir: String,
	pub(in crate::cli::init::apply) domains: Vec<String>,
	pub(in crate::cli::init::apply) listeners: Vec<DesiredListener>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) api: Option<std::collections::BTreeMap<String, String>>,
	pub(in crate::cli::init::apply) dkim: DesiredDkim,
	pub(in crate::cli::init::apply) tls: DesiredTls,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) dns: Option<DesiredDns>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) database: Option<DesiredDatabase>,
	/// The `[acme]` block init writes when ACME is on. Absent on
	/// disk is the "ACME off" shape; a present block carries the
	/// directory URL, contact list, and domains the renewal loop
	/// should request certificates for.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) acme: Option<DesiredAcme>,
	pub(in crate::cli::init::apply) antispam: DesiredAntispam,
	/// The attachment policy for a new install. Never merged into an
	/// existing configuration: see [`NEW_INSTALL_ONLY`].
	pub(in crate::cli::init::apply) attachments: DesiredAttachments,
}

/// Sections and keys `init` writes only into a configuration it creates.
/// On an existing file they are left as the operator has them, so an
/// upgrade that re-runs `init` keeps today's behaviour.
pub(in crate::cli::init::apply) const NEW_INSTALL_ONLY: &[(&str, Option<&str>)] = &[
	("attachments", None),
	("antispam", Some("clamd_on_error")),
	("dkim", Some("domain")),
];

/// The `[attachments]` section for a new install: quarantine disguised
/// files and macros, flag encrypted archives.
#[derive(Debug, Serialize)]
pub(in crate::cli::init::apply) struct DesiredAttachments {
	pub(super) mode: &'static str,
	pub(super) macros: &'static str,
	pub(super) encrypted_archives: &'static str,
}

/// The `[acme]` section `init` writes when the answers (or the
/// public-hostname heuristic) say ACME should be on. `directory_url`
/// is the CA's ACME directory endpoint (Let's Encrypt production
/// today); `contacts` is the list of URIs the CA uses to reach the
/// operator; `domains` is the list of names a certificate should
/// cover; `renew_before_days` matches the schema default (30) so
/// the field appears explicitly and a future change to the schema
/// default flows through `init` as well.
#[derive(Debug, Serialize)]
pub(in crate::cli::init::apply) struct DesiredAcme {
	pub(in crate::cli::init::apply) directory_url: String,
	pub(in crate::cli::init::apply) contacts: Vec<String>,
	pub(in crate::cli::init::apply) domains: Vec<String>,
	pub(in crate::cli::init::apply) renew_before_days: u32,
}

#[derive(Debug, Serialize)]
pub(in crate::cli::init::apply) struct DesiredAntispam {
	/// The stack's clamd; absent when the stack runs no clamav.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) clamd_socket: Option<String>,
	/// What a scan clamd cannot run does; absent without clamd.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(super) clamd_on_error: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub(in crate::cli::init::apply) struct DesiredListener {
	pub(in crate::cli::init::apply) kind: String,
	/// Bind address the listener uses. Always written so the schema
	/// default (`127.0.0.1`) cannot silently take over: an init
	/// config that names only `kind` would bind loopback and miss
	/// every packet the network delivers.
	pub(in crate::cli::init::apply) addr: IpAddr,
}

#[derive(Debug, Serialize)]
pub(in crate::cli::init::apply) struct DesiredDkim {
	pub(in crate::cli::init::apply) selector: String,
	pub(in crate::cli::init::apply) key_file: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) rsa_selector: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) rsa_key_file: Option<String>,
	/// A key of its own for every domain after the first, which signs with
	/// the keys above. Written only into a configuration `init` creates.
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub(in crate::cli::init::apply) domain: Vec<DesiredDkimDomain>,
}

/// One `[[dkim.domain]]` entry `init` writes for a domain of its own.
#[derive(Debug, Serialize)]
pub(in crate::cli::init::apply) struct DesiredDkimDomain {
	pub(in crate::cli::init::apply) name: String,
	pub(in crate::cli::init::apply) selector: String,
	pub(in crate::cli::init::apply) key_file: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) rsa_selector: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) rsa_key_file: Option<String>,
}

#[derive(Debug, Serialize)]
pub(in crate::cli::init::apply) struct DesiredTls {
	pub(in crate::cli::init::apply) cert_file: String,
	pub(in crate::cli::init::apply) key_file: String,
}

#[derive(Debug, Serialize)]
pub(in crate::cli::init::apply) struct DesiredDns {
	pub(in crate::cli::init::apply) provider: String,
	pub(in crate::cli::init::apply) zone: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) token: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) token_file: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli::init::apply) token_env: Option<String>,
}

/// The `[database]` section `init` writes when the operator asks
/// for the database service. The URL is the percent-encoded socket
/// form (`postgres://epistle@%2Frun%2Fpostgresql/epistle`) so the
/// same connection string works on the host (where `init` and
/// `config-check` run) and inside the `mail` container (where
/// `serve` runs). The password file points at the secret the
/// compose file mounts; the `mail` container reads it through the
/// data-directory bind mount at the same path.
#[derive(Debug, Serialize)]
pub(in crate::cli::init::apply) struct DesiredDatabase {
	pub(in crate::cli::init::apply) url: String,
	pub(in crate::cli::init::apply) password_file: String,
}

/// The outcome of trying to merge the desired config with whatever is
/// on disk. `Identical` means the file is already byte-for-byte what we
/// want and stays untouched; `Wrote` means the file did not exist or
/// was rewritten; `Updated` means an existing file was overwritten with
/// a different value.
pub(crate) enum ConfigWrite {
	Identical,
	Wrote,
	Updated,
}
