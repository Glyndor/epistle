//! The `Answers` structure: every value the operator passes to
//! `epistle init`, whether through the file or through the assistant.
//!
//! The same struct serialises into the `--answers` TOML file and gets
//! filled field by field by the assistant. One code path: the assistant
//! validates each entry with the same rule as the file, so a mistake
//! rejected by the file is rejected by the assistant with the same
//! message string. The validation routine lives in
//! [`answers_validate.rs`](self) and is invoked through
//! [`Answers::validate`].

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level mode the operator chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
	/// Operator publishes DNS records by hand. `[dns]` is forbidden.
	Manual,
	/// `init` will publish records through the configured provider.
	Automatic,
}

/// DNS provider credentials and zone. Exactly one of `token_file`,
/// `token_env`, or inline `token` must be set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsAnswers {
	/// Provider id (e.g. `"cloudflare"`).
	pub provider: String,
	/// The zone the token is scoped to. Every configured domain must
	/// fall inside it.
	pub zone: String,
	/// Inline API token. Discouraged; accepted with one warning.
	#[serde(default)]
	pub token: Option<String>,
	/// Path to a `0600` file holding the token.
	#[serde(default)]
	pub token_file: Option<PathBuf>,
	/// Environment variable holding the token.
	#[serde(default)]
	pub token_env: Option<String>,
}

/// The set of services the operator wants to expose.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Services {
	/// IMAP listener (defaults to `true`).
	#[serde(default = "default_true")]
	pub imap: bool,
	/// Submission listener (defaults to `true`).
	#[serde(default = "default_true")]
	pub submission: bool,
	/// POP3 listener (defaults to `false`).
	#[serde(default)]
	pub pop3: bool,
	/// ManageSieve listener (defaults to `false`).
	#[serde(default)]
	pub managesieve: bool,
	/// WebDAV listener (defaults to `false`).
	#[serde(default)]
	pub webdav: bool,
	/// Management API listener (defaults to `false`).
	#[serde(default)]
	pub api: bool,
}

const fn default_true() -> bool {
	true
}

impl Default for Services {
	fn default() -> Self {
		Self {
			imap: true,
			submission: true,
			pop3: false,
			managesieve: false,
			webdav: false,
			api: false,
		}
	}
}

/// The whole operator input. Serialises into the `--answers` file,
/// gets filled by the assistant. Every field is named after the matching
/// TOML key so a single set of names drives both paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answers {
	/// `"manual"` or `"automatic"`.
	pub mode: Mode,
	/// Fully-qualified hostname the server identifies as.
	pub hostname: String,
	/// Domains this server accepts mail for.
	pub domains: Vec<String>,
	/// Optional public IPv4 (must be global unicast when present).
	#[serde(default)]
	pub public_ipv4: Option<Ipv4Addr>,
	/// Optional public IPv6 (must be global unicast when present).
	#[serde(default)]
	pub public_ipv6: Option<Ipv6Addr>,
	/// `data_dir` written into the generated config.
	pub data_dir: PathBuf,
	/// Path the generated config is written to.
	pub config_path: PathBuf,
	/// DNS provider settings, mandatory in automatic mode, forbidden in
	/// manual mode.
	#[serde(default)]
	pub dns: Option<DnsAnswers>,
	/// Which services to expose.
	#[serde(default)]
	pub services: Services,
}

/// A non-fatal problem the operator should see before the file is
/// accepted: the value is allowed but the operator should know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
	/// The field the warning refers to.
	pub field: String,
	/// The human-readable message.
	pub message: String,
}

impl std::fmt::Display for Warning {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}: {}", self.field, self.message)
	}
}

/// A problem that must be fixed before `init` can proceed. Each variant
/// owns its own message string so a taint analyser cannot read a constant
/// into a credential sink by mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
	/// `hostname` is empty, not an FQDN, or equal to one of `domains`.
	Hostname(String),
	/// `domains` is empty.
	DomainsEmpty,
	/// A domain in `domains` fails `crate::domain::normalize` or equals
	/// the hostname.
	Domain { value: String, reason: String },
	/// Two entries in `domains` normalise to the same A-label.
	DomainsDuplicate { a: String, b: String },
	/// `public_ipv4` is not a global unicast address.
	PublicIpv4 { value: String, reason: String },
	/// `public_ipv6` is not a global unicast address.
	PublicIpv6 { value: String, reason: String },
	/// Automatic mode was selected without a `[dns]` section.
	DnsRequired,
	/// Manual mode was selected with a `[dns]` section present.
	DnsForbidden,
	/// `dns.zone` is missing or empty.
	DnsZoneMissing,
	/// `dns.zone` is not a valid domain name (fails
	/// `crate::domain::normalize`: bad shape, bad punycode, confusable
	/// look-alike, etc.). Carries the reason so the operator sees
	/// what to fix without having to read the validator's source.
	DnsZoneInvalid {
		value: String,
		reason: String,
	},
	/// `dns.provider` is missing or empty.
	DnsProviderMissing,
	/// A domain does not fall inside `dns.zone`.
	DnsZoneScope { domain: String, zone: String },
	/// `[dns]` declared more than one of `token`/`token_file`/`token_env`.
	DnsTokenAmbiguous,
	/// `[dns]` declared none of `token`/`token_file`/`token_env`.
	DnsTokenMissing,
	/// `data_dir` is not absolute.
	DataDirNotAbsolute,
	/// `config_path` is not absolute.
	ConfigPathNotAbsolute,
	/// `config_path` has no usable file-name component (e.g. `/` or
	/// `.`). The apply phase rejects the same shape at the staging
	/// step, but by then the data directory and every key are
	/// already on disk; the validator catches it earlier so nothing
	/// is touched.
	ConfigPathNoFileName,
	/// `config_path` equals `data_dir`. Writing the config and the
	/// keys into the same directory is never what the operator
	/// intended; a hand-crafted config that pointed at the data
	/// directory would also let the staging step overwrite a key.
	ConfigPathEqualsDataDir,
	/// `services.api = true`: init cannot mint a management API
	/// credential, so the operator must enable the api service by
	/// editing the `[api]` section of the generated config after
	/// `init` returns.
	ApiUnsupported,
}

impl std::fmt::Display for Invalid {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Invalid::Hostname(why) => write!(f, "hostname: {why}"),
			Invalid::DomainsEmpty => f.write_str("domains: must contain at least one domain"),
			Invalid::Domain { value, reason } => write!(f, "domains: {value:?}: {reason}"),
			Invalid::DomainsDuplicate { a, b } => {
				write!(f, "domains: {a:?} and {b:?} normalise to the same A-label")
			}
			Invalid::PublicIpv4 { value, reason } => {
				write!(f, "public_ipv4: {value:?} {reason}")
			}
			Invalid::PublicIpv6 { value, reason } => {
				write!(f, "public_ipv6: {value:?} {reason}")
			}
			Invalid::DnsRequired => f.write_str("mode = \"automatic\" requires [dns]"),
			Invalid::DnsForbidden => f.write_str("mode = \"manual\" must not have [dns]"),
			Invalid::DnsZoneMissing => f.write_str("dns.zone must be set"),
			Invalid::DnsZoneInvalid { value, reason } => {
				write!(f, "dns.zone {value:?} {reason}")
			}
			Invalid::DnsProviderMissing => f.write_str("dns.provider must be set"),
			Invalid::DnsZoneScope { domain, zone } => {
				write!(f, "domains: {domain:?} is not inside dns.zone {zone:?}")
			}
			Invalid::DnsTokenAmbiguous => {
				f.write_str("dns: set exactly one of token, token_file, token_env")
			}
			Invalid::DnsTokenMissing => f.write_str("dns: set one of token, token_file, token_env"),
			Invalid::DataDirNotAbsolute => f.write_str("data_dir: must be an absolute path"),
			Invalid::ConfigPathNotAbsolute => f.write_str("config_path: must be an absolute path"),
			Invalid::ConfigPathNoFileName => {
				f.write_str("config_path: must have a usable file name (not `/` or `.`)")
			}
			Invalid::ConfigPathEqualsDataDir => {
				f.write_str("config_path: must not equal data_dir")
			}
			Invalid::ApiUnsupported => f.write_str(
				"services.api: enable the management API by editing the [api] section of the generated config after init; init does not generate an api credential",
			),
		}
	}
}

impl Answers {
	/// Validate the answers, collecting every problem instead of stopping
	/// at the first one. Used by both the `--answers` file path and the
	/// assistant path so the two never disagree.
	///
	/// Returns `Ok(warnings)` when every required rule passes. Warnings
	/// (e.g. an inline API token) are non-fatal but always surfaced.
	pub fn validate(&self) -> Result<Vec<Warning>, Vec<Invalid>> {
		answers_validate::validate(self)
	}

	/// Replace every Unicode (U-label) hostname or domain in the
	/// answers with its ASCII A-label form. The validator and the
	/// apply phase both already pass U-labels through
	/// `crate::domain::normalize`; persisting the A-label here
	/// keeps that work and stops the ASCII-only consumers (the
	/// certificate builder, the TOML config) from ever seeing a
	/// U-label. ASCII-only inputs are returned unchanged.
	pub fn normalise(&mut self) {
		if let Ok(norm) = crate::domain::normalize(&self.hostname) {
			self.hostname = norm;
		}
		self.domains = std::mem::take(&mut self.domains)
			.into_iter()
			.map(|d| crate::domain::normalize(&d).unwrap_or(d))
			.collect();
	}

	/// Build the TOML template printed by `--print-answers` and
	/// distributed in the docs. Comments name every field; defaults match
	/// the documented operator-facing values. Every line is a TOML comment
	/// or key/value pair, so the operator can redirect the output to a
	/// file and load it back through `toml::from_str` once the values are
	/// filled in.
	pub fn template() -> String {
		"# use this file as a starting point: copy it, fill in the values, \
		 and pass it to \"epistle init --answers FILE\".\n\
		 # Every key is required unless a comment says otherwise.\n\n\
		 mode = \"manual\"                   # \"manual\" or \"automatic\"\n\
		 hostname = \"mail.example.org\"     # FQDN the server identifies as\n\
		 domains = [\"example.org\"]         # at least one; not equal to hostname\n\
		 # public_ipv4 = \"203.0.113.10\"    # optional; must be a global unicast address\n\
		 # public_ipv6 = \"2001:db8::10\"    # optional; must be a global unicast address\n\
		 data_dir = \"/var/lib/glyndor/epistle\"\n\
		 config_path = \"/etc/epistle/mail.toml\"\n\n\
		 # [dns]                             # only with mode = \"automatic\"\n\
		 # provider = \"cloudflare\"          # cloudflare, route53, dnsimple, ...\n\
		 # zone = \"example.org\"\n\
		 # token_file = \"/run/secrets/epistle-dns\"  # or token_env = \"NAME\"; token = \"...\" is accepted with one warning\n\n\
		 [services]                        # each true | false; defaults: imap, submission true; the rest false\n\
		 imap = true\n\
		 submission = true\n\
		 # pop3 = false\n\
		 # managesieve = false\n\
		 # webdav = false\n\
		 # api = false                      # enable the management API by editing the [api] section of the generated config; init does not mint an api credential\n"
			.to_string()
	}
}

#[cfg(test)]
#[path = "answers_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "answers_tests_b.rs"]
mod tests_b;

#[path = "answers_validate.rs"]
mod answers_validate;
