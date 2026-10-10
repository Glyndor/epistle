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

/// ACME (automatic certificate issuance) overrides. When the
/// section is absent, init falls back to its heuristic: a public
/// hostname gets Let's Encrypt production; a loopback or
/// reserved-TLD hostname gets nothing. Setting `enabled = true`
/// forces ACME on for whatever the hostname is (init will refuse
/// to write a `[acme]` block for a non-public hostname because the
/// HTTP-01 challenge would never resolve, but the boolean is still
/// the operator's explicit opt-in). Setting `enabled = false`
/// forces it off even on a public hostname, which is what an
/// operator with their own certificate uses. `contact` overrides
/// the default `mailto:postmaster@<first domain>`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeAnswers {
	/// Force ACME on (`true`) or off (`false`). Absent lets the
	/// public-hostname heuristic decide.
	#[serde(default)]
	pub enabled: Option<bool>,
	/// Contact URI the certificate authority uses to reach the
	/// operator (let's encrypt sends a verification email when an
	/// account is created and a heads-up before a certificate
	/// expires). Absent defaults to `mailto:postmaster@<first
	/// configured domain>`.
	#[serde(default)]
	pub contact: Option<String>,
}

/// The set of services the operator wants to expose.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
	/// Bring up the stack's PostgreSQL (directory, bans, antispam).
	/// When `true`, `init` writes a `[database]` section to the config,
	/// mints the database password, and adds the postgres service to
	/// the compose file. No default: a missing field is an error that
	/// names `services.database` so the operator has to make the
	/// choice explicitly.
	pub database: bool,
}

const fn default_true() -> bool {
	true
}

impl Default for Services {
	fn default() -> Self {
		// `database` is the only field without a `serde(default)` and
		// without an opinion here. The file path requires the
		// operator to state the choice, so the `Default` impl mirrors
		// what a hand-written `Services` with the same listener
		// defaults would look like for a test that does not care
		// about the database. Tests that do care pass `database`
		// explicitly.
		Self {
			imap: true,
			submission: true,
			pop3: false,
			managesieve: false,
			webdav: false,
			api: false,
			database: false,
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
	/// Which services to expose. The whole `[services]` table is
	/// required: a missing table must not silently default to
	/// `database = false` and let a hand-typed answers file skip the
	/// explicit choice. Tests pin this with
	/// `services_table_is_required`.
	pub services: Services,
	/// Optional override for the `mail` service image. The default is
	/// `ghcr.io/glyndor/epistle:<CARGO_PKG_VERSION>` resolved at build
	/// time, which is what a release-pinned install uses. Tests and
	/// local builds pass a different image (e.g.
	/// `localhost/epistle:dev`). `None` lets the default apply.
	/// Validated non-empty and whitespace-free when set so the compose
	/// writer cannot produce a bare `image:` key or a value that
	/// splits across two array entries.
	#[serde(default)]
	pub image: Option<String>,
	/// ACME overrides. Absent lets init decide based on the
	/// hostname (a public hostname gets Let's Encrypt production;
	/// loopback or reserved-TLD hostnames get nothing). The
	/// `[acme]` block init writes into the config follows this
	/// flag plus `contact`.
	#[serde(default)]
	pub acme: Option<AcmeAnswers>,
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
	DnsZoneMalformed { value: String, reason: String },
	/// `dns.provider` is missing or empty.
	DnsProviderMissing,
	/// `dns.provider` is not one of the supported provider names. Carries
	/// the bad value and a comma-separated list of supported names so the
	/// operator sees what they could have written.
	DnsProviderUnsupported { value: String, supported: String },
	/// A domain does not fall inside `dns.zone`.
	DnsZoneScope { domain: String, zone: String },
	/// `[dns]` declared more than one of `token`/`token_file`/`token_env`.
	DnsTokenAmbiguous,
	/// `[dns]` declared none of `token`/`token_file`/`token_env`.
	DnsTokenMissing,
	/// `data_dir` is not absolute.
	DataDirNotAbsolute,
	/// The data mount would expose the user home or host runtime directories.
	DataDirUnsafe { suggested: String },
	/// The current account home could not be resolved safely.
	DataDirHomeUnavailable(String),
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
	/// `config_path` is inside `<data_dir>/keys`. `init` owns that
	/// directory and would race the staging step against itself.
	ConfigPathInsideKeysDir,
	/// `config_path`'s directory and `data_dir` overlap, so the
	/// compose file would mount the same path twice (once for
	/// the data directory, once for the config directory) and
	/// podman would refuse the container. The config mount is
	/// read-only, so a single shared mount cannot satisfy both
	/// roles. Either direction is caught: a `config_path` whose
	/// parent equals or sits inside `data_dir`, and a `data_dir`
	/// that equals or sits inside `config_path`'s parent. The
	/// comparison normalises `.` and `..` lexically and
	/// canonicalises both paths when they exist on disk, so
	/// `data_dir = "/srv/epistle/data"` and
	/// `config_path = "/srv/epistle/spare/../data/mail.toml"`
	/// are caught here even though the textual paths look
	/// disjoint.
	ConfigMountsOverlap {
		data_dir: String,
		config_dir: String,
	},
	/// `data_dir` or `config_path` contains a `..` component that
	/// cannot be resolved lexically (e.g. `data_dir = "/../foo"`).
	/// The path is absolute but tries to escape its root before
	/// any directory is named, so the lexical normalisation that
	/// the overlap check relies on has nothing to compare. The
	/// validator refuses the input before any effect rather than
	/// silently normalising to a path the operator did not write.
	PathParentEscapesRoot { field: String, value: String },
	/// `data_dir` or `config_path` contains a `$` that compose
	/// would interpolate at `podup config` time. The compose
	/// file mounts the two paths verbatim on both sides of the
	/// colon; a `$VAR` in the source path resolves to the empty
	/// string (or a value `podup` reads from the host
	/// environment) while the rendered `mail.toml` keeps the
	/// literal `$VAR` in its `data` and key paths, and the
	/// container cannot find the keys the host generated. The
	/// validator catches the `$` before any effect, and the
	/// operator has to write the resolved path directly.
	PathInterpolated { field: String, value: String },
	/// `services.api = true`: init cannot mint a management API
	/// credential, so the operator must enable the api service by
	/// editing the `[api]` section of the generated config after
	/// `init` returns.
	ApiUnsupported,
	/// `image` is set but empty or contains whitespace. The
	/// compose file pins the image as a single string, so an empty
	/// value would resolve to a bare `image:` key and whitespace
	/// inside would split it across two values.
	ImageMalformed(String),
	/// `image` has no tag or digest. The compose writer needs a
	/// pinned reference; an untagged image (e.g. `ghcr.io/.../epistle`)
	/// would default to `:latest` and break reproducible
	/// installs, which is exactly what the operator avoided by
	/// using `init` instead of `podup run`. The same check rejects
	/// an explicit `:latest` tag, which is no better.
	ImageUntagged(String),
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
			Invalid::DnsZoneMalformed { value, reason } => {
				write!(f, "dns.zone {value:?} {reason}")
			}
			Invalid::DnsProviderMissing => f.write_str("dns.provider must be set"),
			Invalid::DnsProviderUnsupported { value, supported } => write!(
				f,
				"dns.provider {value:?} is not a supported provider; supported: {supported}"
			),
			Invalid::DnsZoneScope { domain, zone } => {
				write!(f, "domains: {domain:?} is not inside dns.zone {zone:?}")
			}
			Invalid::DnsTokenAmbiguous => {
				f.write_str("dns: set exactly one of token, token_file, token_env")
			}
			Invalid::DnsTokenMissing => f.write_str("dns: set one of token, token_file, token_env"),
			Invalid::DataDirUnsafe { suggested } => write!(f,
                "data_dir: must exclude the user home, Podman storage and systemd units; a writable container mount would expose host services and backups would include container storage; use {suggested}"),
            Invalid::DataDirHomeUnavailable(reason) => write!(f, "data_dir: cannot determine the current user home: {reason}"),
			Invalid::DataDirNotAbsolute => f.write_str("data_dir: must be an absolute path"),
			Invalid::ConfigPathNotAbsolute => f.write_str("config_path: must be an absolute path"),
			Invalid::ConfigPathNoFileName => f.write_str(
				"config_path: must end with a usable file name (not `/`, `.`, `..`, or a trailing `/`)",
			),
			Invalid::ConfigPathEqualsDataDir => {
				f.write_str("config_path: must not equal data_dir")
			}
			Invalid::ConfigPathInsideKeysDir => f.write_str(
				"config_path: must not be inside data_dir/keys",
			),
			Invalid::ConfigMountsOverlap {
				data_dir,
				config_dir,
			} => write!(
				f,
				"data_dir {data_dir:?} and config_path's directory {config_dir:?} must not overlap; \
				 the compose file mounts both, and podman refuses duplicate mount destinations"
			),
			Invalid::PathParentEscapesRoot { field, value } => write!(
				f,
				"{field} {value:?}: contains `..` that escapes the path root; \
				 write the path without `..` components"
			),
			Invalid::PathInterpolated { field, value } => write!(
				f,
				"{field} {value:?}: must not contain a `$`; compose would interpolate it \
				 and the rendered mail.toml would still carry the literal `$VAR` in its \
				 data and key paths, so the container could not find the generated keys. \
				 Write the resolved path directly."
			),
			Invalid::ApiUnsupported => f.write_str(
				"services.api: enable the management API by editing the [api] section of the generated config after init; init does not generate an api credential",
			),
			Invalid::ImageMalformed(value) => write!(
				f,
				"image {value:?}: must be non-empty and contain no whitespace"
			),
			Invalid::ImageUntagged(value) => write!(
				f,
				"image {value:?}: must include a tag that is not 'latest' or a @sha256: digest"
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

	/// True when the hostname resolves in the public DNS: not
	/// loopback, not an IP literal, not a name under a reserved
	/// TLD (`.local`, `.internal`, `.test`, `.example`). Init uses
	/// this to decide whether ACME auto-enables: the Let's Encrypt
	/// HTTP-01 challenge connects to the host on port 80, so a
	/// loopback or reserved-TLD hostname would never resolve.
	/// The list of reserved TLDs is the RFC 6762 / RFC 2606 set
	/// plus `.internal`, the name an internal split-horizon DNS
	/// server hands out, and `.example`, the documentation TLD.
	pub fn hostname_is_public(&self) -> bool {
		is_public_hostname(&self.hostname)
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
		 data_dir = \"/var/lib/glyndor/epistle/data\"\n\
		 config_path = \"/etc/epistle/mail.toml\"\n\
		 # image = \"ghcr.io/glyndor/epistle:0.8\"   # optional override; default is the build-time version\n\n\
		 # [dns]                             # only with mode = \"automatic\"\n\
		 # provider = \"cloudflare\"          # cloudflare, route53, dnsimple, ...\n\
		 # zone = \"example.org\"\n\
		 # token_file = \"/run/secrets/epistle-dns\"  # or token_env = \"NAME\"; token = \"...\" is accepted with one warning\n\n\
		 [acme]                             # optional; init enables ACME on its own for a public hostname\n\
		 # enabled = true                    # set false to skip Let's Encrypt even on a public hostname (you supply your own cert)\n\
		 # contact = \"mailto:postmaster@example.org\"  # optional override; defaults to postmaster@<first configured domain>\n\n\
		 [services]                        # required; each true | false; defaults: imap, submission true; the rest false\n\
		 imap = true\n\
		 submission = true\n\
		 # pop3 = false\n\
		 # managesieve = false\n\
		 # webdav = false\n\
		 # api = false                      # enable the management API by editing the [api] section of the generated config; init does not mint an api credential\n\
		 database = false                  # bring up the stack's PostgreSQL (directory, bans, antispam); init must state this explicitly, no default\n"
			.to_string()
	}
}

/// TLDs that are not delegated in the public DNS. Init refuses
/// to enable ACME for a name under one of these: the HTTP-01
/// challenge would never reach the responder, and the resulting
/// renewal loop would log failures every 12 hours forever. The
/// list is the RFC 6762 multicast DNS name, the RFC 2606 test and
/// example TLDs, and `.internal`, the name a private split-horizon
/// DNS server hands out for hosts that should never appear on the
/// public internet.
const RESERVED_TLDS: &[&str] = &["local", "internal", "test", "example"];

/// True when `hostname` is one init would auto-enable ACME for:
/// a real DNS name (no IP literal), not under a reserved TLD,
/// not a loopback name. The check is deliberately conservative: a
/// false positive would write an `[acme]` block that cannot
/// succeed; a false negative only means the operator has to set
/// `acme.enabled = true` themselves.
pub fn is_public_hostname(hostname: &str) -> bool {
	if hostname.is_empty() {
		return false;
	}
	// IP literal (v4 or v6) -> not public. `IpAddr::from_str`
	// covers the canonical forms (`127.0.0.1`, `::1`,
	// `[::1]`); the surrounding brackets are the URL form, not
	// what an FQDN would carry.
	if hostname.parse::<std::net::IpAddr>().is_ok() {
		return false;
	}
	// Loopback name (`localhost` or a name that resolves to it).
	// The set is small on purpose: `.localhost` is the RFC 6762
	// form, `localhost` is the host file shortcut, and the
	// bracketed forms are rejected up front (they parse as IPs).
	if hostname.eq_ignore_ascii_case("localhost")
		|| hostname.eq_ignore_ascii_case("localhost.localdomain")
	{
		return false;
	}
	// Walk the labels, top down, to find the TLD. A name with no
	// labels (impossible after the empty-string check above, but
	// belt and braces) is treated as private.
	let tld = match hostname.rsplit('.').next() {
		Some(label) if !label.is_empty() => label,
		_ => return false,
	};
	let tld_lc = tld.to_ascii_lowercase();
	if RESERVED_TLDS.iter().any(|reserved| *reserved == tld_lc) {
		return false;
	}
	true
}

#[cfg(test)]
#[path = "answers_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "answers_tests_validate.rs"]
mod tests_validate;

#[cfg(test)]
#[path = "answers_tests_deserialise.rs"]
mod tests_deserialise;

#[cfg(test)]
#[path = "answers_tests_messages.rs"]
mod tests_messages;

#[cfg(test)]
#[path = "answers_tests_dns.rs"]
mod tests_dns;

#[cfg(test)]
#[path = "answers_tests_config_path.rs"]
mod tests_config_path;

#[cfg(test)]
#[path = "answers_tests_paths_overlap.rs"]
mod tests_paths_overlap;

#[cfg(test)]
#[path = "answers_tests_services.rs"]
mod tests_services;

#[path = "answers_validate.rs"]
mod answers_validate;

#[path = "answers_data_dir.rs"]
mod data_dir;
