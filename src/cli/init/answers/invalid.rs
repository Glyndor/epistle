//! Answer validation failures and operator diagnostics.

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
	/// `data_dir` or `config_path` carries a control character or an
	/// invisible formatting character. The path is written into the plan
	/// the operator confirms and into the final report, so an escape
	/// sequence arriving from an answers file or from a saved draft
	/// could repaint the terminal or hide part of what is shown. The
	/// validator refuses it before any effect, the same place that
	/// refuses the `$` shape below.
	PathControl { field: String, value: String },
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
	/// `[first_account]` names an address, an account or a display
	/// name that cannot be created. Carries the reason.
	FirstAccount(String),
	/// A `[resources.<service>]` table names no service of the stack, or
	/// one of its values is not a limit podup can apply.
	Resources { field: String, reason: String },
}

impl std::fmt::Display for Invalid {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Invalid::Hostname(why) => write!(f, "hostname: {why}"),
			Invalid::Resources { field, reason } => write!(f, "{field}: {reason}"),
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
				write!(f, "dns.zone {value:?}: {reason}")
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
			Invalid::DataDirUnsafe { suggested } => write!(
				f,
				"data_dir: must exclude the user home, Podman storage and systemd units; a writable container mount would expose host services and backups would include container storage; use {suggested}"
			),
			Invalid::DataDirHomeUnavailable(reason) => write!(
				f,
				"data_dir: cannot determine the current user home: {reason}"
			),
			Invalid::DataDirNotAbsolute => f.write_str("data_dir: must be an absolute path"),
			Invalid::ConfigPathNotAbsolute => f.write_str("config_path: must be an absolute path"),
			Invalid::ConfigPathNoFileName => f.write_str(
				"config_path: must end with a usable file name (not `/`, `.`, `..`, or a trailing `/`)",
			),
			Invalid::ConfigPathEqualsDataDir => f.write_str("config_path: must not equal data_dir"),
			Invalid::ConfigPathInsideKeysDir => {
				f.write_str("config_path: must not be inside data_dir/keys")
			}
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
			Invalid::PathControl { field, value } => write!(
				f,
				"{field} {value:?}: must not contain control or invisible formatting \
				 characters; the plan and the report are printed on the terminal, so an \
				 escape sequence in the path would repaint what you are confirming. \
				 Write the plain path."
			),
			Invalid::PathInterpolated { field, value } => write!(
				f,
				"{field} {value:?}: must not contain a `$`; compose would interpolate it \
				 while the rendered mail.toml keeps the literal `$VAR` (or expands it itself, \
				 and stops when the variable is unset), so the container could not find \
				 the file the host expects. Write the resolved path directly."
			),
			Invalid::ImageMalformed(value) => write!(
				f,
				"image {value:?}: must be non-empty and contain no whitespace"
			),
			Invalid::ImageUntagged(value) => write!(
				f,
				"image {value:?}: must include a tag that is not 'latest' or a @sha256: digest"
			),
			Invalid::FirstAccount(why) => write!(f, "first_account: {why}"),
		}
	}
}
