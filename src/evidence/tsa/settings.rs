//! Which timestamp authorities to ask, and whether to ask at all.
//!
//! Timestamping is on by default as soon as evidence is kept. The default
//! authority is Sectigo's public time stamping service, free to use without
//! an account, answered over HTTPS, and signing with RSA and SHA-384, which
//! this verifier supports. Its tokens are trusted only when their chain
//! reaches the pinned key of "Sectigo Public Time Stamping Root R46"
//! (SubjectPublicKeyInfo SHA-256 below), whether that root arrives
//! self-signed or cross-signed by USERTrust.
//!
//! Operators may list their own authorities, each with the keys it is
//! trusted under. FreeTSA is not a default: its tokens are signed with
//! ECDSA P-384 over SHA-512, which `ring` does not verify.
//!
//! The settings live in `<evidence>/timestamp.json`, written by the CLI;
//! every change is also recorded in the evidence chain.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::evidence::record::hash_from_hex;

/// The default authority.
pub const DEFAULT_TSA_URL: &str = "https://timestamp.sectigo.com";
/// SHA-256 of the SubjectPublicKeyInfo of Sectigo Public Time Stamping
/// Root R46, the anchor of [`DEFAULT_TSA_URL`].
pub const DEFAULT_TSA_ANCHOR: &str =
	"a4db8668c6796ebf476ddc5ace453a9260dbd4dbb09f51ecec9a839003824795";
/// The most authorities that may be listed.
pub const MAX_AUTHORITIES: usize = 8;
/// The most anchors one authority may list.
pub const MAX_ANCHORS: usize = 8;

const FILE: &str = "timestamp.json";

/// One authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authority {
	/// Where RFC 3161 requests are POSTed.
	pub url: String,
	/// Hex SHA-256 of the SubjectPublicKeyInfo of each trusted key.
	pub anchors: Vec<String>,
	/// The policy OID (dotted, `1.2.3.4`) its tokens must carry, when the
	/// operator requires one.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub policy: Option<String>,
	/// A test authority on loopback, reached over plain HTTP. Refused
	/// outside the test build.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub local_test: bool,
	/// A file (`0600`, owned by the server user) holding a bearer token for
	/// an authority that requires one. Only the path is kept here; the
	/// token is read when a request is made and never stored or recorded.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub token_file: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for Authority {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("Authority")
			.field("host", &self.display())
			.field("anchors", &self.anchors)
			.field("policy", &self.policy)
			.field("local_test", &self.local_test)
			.field("token_file", &self.token_file.as_ref().map(|_| "<set>"))
			.finish()
	}
}

/// The timestamp settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
	/// Whether checkpoints are timestamped.
	pub enabled: bool,
	/// The authorities, tried in order.
	pub authorities: Vec<Authority>,
}

impl Default for Settings {
	fn default() -> Self {
		Settings {
			enabled: true,
			authorities: vec![Authority {
				url: DEFAULT_TSA_URL.to_string(),
				anchors: vec![DEFAULT_TSA_ANCHOR.to_string()],
				policy: None,
				local_test: false,
				token_file: None,
			}],
		}
	}
}

impl Authority {
	/// How the authority is named in output and errors: its host only, so
	/// nothing a URL could carry (credentials, a query) is ever printed.
	pub fn display(&self) -> String {
		url::Url::parse(&self.url)
			.ok()
			.and_then(|url| url.host_str().map(str::to_string))
			.unwrap_or_else(|| "<invalid URL>".to_string())
	}

	/// The required policy as DER OID content octets, when one is set and
	/// well formed.
	pub fn policy_oid(&self) -> Option<Vec<u8>> {
		self.policy.as_deref().and_then(oid_from_dotted)
	}

	/// The anchors as hashes; a malformed one is skipped (and refused when
	/// the settings are saved).
	pub fn anchor_hashes(&self) -> Vec<[u8; 32]> {
		self.anchors
			.iter()
			.filter_map(|anchor| hash_from_hex(anchor))
			.collect()
	}
}

/// Why settings were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsError(pub String);

impl std::fmt::Display for SettingsError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str(&self.0)
	}
}

impl Settings {
	/// Check the settings: at most [`MAX_AUTHORITIES`], each an `https` URL
	/// (plain `http` only to a loopback address) with one to
	/// [`MAX_ANCHORS`] SHA-256 anchors. Enabled settings need at least one
	/// authority.
	pub fn validate(&self) -> Result<(), SettingsError> {
		if self.authorities.len() > MAX_AUTHORITIES {
			return Err(SettingsError(format!(
				"at most {MAX_AUTHORITIES} timestamp authorities may be listed"
			)));
		}
		if self.enabled && self.authorities.is_empty() {
			return Err(SettingsError(
				"timestamping needs at least one authority".into(),
			));
		}
		for authority in &self.authorities {
			if url::Url::parse(&authority.url)
				.is_ok_and(|url| !url.username().is_empty() || url.password().is_some())
			{
				return Err(SettingsError(
					"a timestamp authority URL must not carry credentials (use token_file)".into(),
				));
			}
			// Plain HTTP exists for the loopback authority the tests run;
			// a release build never accepts it.
			check_url(&authority.url, authority.local_test && cfg!(test))?;
			if authority.anchors.is_empty() || authority.anchors.len() > MAX_ANCHORS {
				return Err(SettingsError(format!(
					"each authority needs 1 to {MAX_ANCHORS} anchors"
				)));
			}
			if authority.policy.is_some() && authority.policy_oid().is_none() {
				return Err(SettingsError(
					"a policy is a dotted object identifier".into(),
				));
			}
			if authority
				.anchors
				.iter()
				.any(|anchor| hash_from_hex(anchor).is_none())
			{
				return Err(SettingsError(
					"an anchor is the lowercase hex SHA-256 of a SubjectPublicKeyInfo".into(),
				));
			}
		}
		Ok(())
	}
}

/// The DER content octets of a dotted OID (`1.2.840.113549`), or `None`.
pub fn oid_from_dotted(dotted: &str) -> Option<Vec<u8>> {
	let arcs: Vec<u64> = dotted
		.split('.')
		.map(|arc| {
			arc.parse()
				.ok()
				.filter(|_| !arc.is_empty() && arc.len() <= 19)
		})
		.collect::<Option<_>>()?;
	if arcs.len() < 2 || arcs.len() > 32 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
		return None;
	}
	let mut out = Vec::new();
	let first = arcs[0].checked_mul(40)?.checked_add(arcs[1])?;
	for arc in std::iter::once(first).chain(arcs[2..].iter().copied()) {
		let mut groups = vec![(arc & 0x7f) as u8];
		let mut rest = arc >> 7;
		while rest > 0 {
			groups.push((rest & 0x7f) as u8 | 0x80);
			rest >>= 7;
		}
		out.extend(groups.iter().rev());
	}
	Some(out)
}

/// Refuse a URL that is not `https`, or plain `http` to loopback when
/// `plain_allowed`.
fn check_url(value: &str, plain_allowed: bool) -> Result<(), SettingsError> {
	let url = url::Url::parse(value)
		.map_err(|_| SettingsError("a timestamp authority URL does not parse".into()))?;
	let loopback = match url.host() {
		Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
		Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
		Some(url::Host::Domain(name)) => name == "localhost",
		None => false,
	};
	match url.scheme() {
		"https" if url.host().is_some() => Ok(()),
		"http" if plain_allowed && loopback => Ok(()),
		_ => Err(SettingsError(
			"a timestamp authority URL must be https (plain http only for a local test authority)"
				.into(),
		)),
	}
}

/// The settings under `evidence_root`: the defaults when none were saved.
///
/// A file that is a link, is not owned by this user, or that group or
/// others may write, is refused (`PermissionDenied`): whoever can write it
/// decides which authorities are trusted. A file that does not parse or
/// does not validate is refused (`InvalidData`). None of these falls back
/// to the defaults; the caller keeps the settings it had, or stops.
pub fn load(evidence_root: &Path) -> std::io::Result<Settings> {
	let path = evidence_root.join(FILE);
	match std::fs::symlink_metadata(&path) {
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			return Ok(Settings::default());
		}
		Err(error) => return Err(error),
		Ok(meta) => check_owner_only(&meta)?,
	}
	let Some(bytes) = crate::evidence::checkpoint::read_bounded(&path, 64 * 1024)? else {
		return Ok(Settings::default());
	};
	let settings: Settings = serde_json::from_slice(&bytes)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
	settings
		.validate()
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.0))?;
	Ok(settings)
}

fn check_owner_only(meta: &std::fs::Metadata) -> std::io::Result<()> {
	use std::os::unix::fs::MetadataExt;
	// SAFETY: geteuid has no preconditions and cannot fail.
	let me = unsafe { libc::geteuid() };
	if !meta.file_type().is_file() || meta.uid() != me || meta.mode() & 0o022 != 0 {
		return Err(std::io::Error::new(
			std::io::ErrorKind::PermissionDenied,
			"timestamp settings are writable by other users: refused",
		));
	}
	Ok(())
}

/// Save `settings` under `evidence_root` after checking them.
pub fn save(evidence_root: &Path, settings: &Settings) -> std::io::Result<()> {
	settings
		.validate()
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error.0))?;
	crate::evidence::chain::create_private_dir(evidence_root)?;
	let bytes = serde_json::to_vec_pretty(settings).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&evidence_root.join(FILE), &bytes)
}

/// Read the bearer token in `path`: a regular file (not a link), owned by
/// the server user, readable by nobody else, at most 4 KiB.
pub fn read_token(path: &Path) -> std::io::Result<String> {
	use std::os::unix::fs::MetadataExt;
	let refused = || {
		std::io::Error::new(
			std::io::ErrorKind::PermissionDenied,
			"a TSA token file must be 0600 and owned by the server user",
		)
	};
	let meta = std::fs::symlink_metadata(path)?;
	// SAFETY: geteuid has no preconditions and cannot fail.
	let me = unsafe { libc::geteuid() };
	if !meta.file_type().is_file() || meta.uid() != me || meta.mode() & 0o077 != 0 {
		return Err(refused());
	}
	let bytes = crate::evidence::checkpoint::read_bounded(path, 4096)?.ok_or_else(refused)?;
	let token = String::from_utf8(bytes).map_err(|_| {
		std::io::Error::new(std::io::ErrorKind::InvalidData, "a TSA token is not text")
	})?;
	let token = token.trim().to_string();
	if token.is_empty() || token.chars().any(|c| c.is_control()) {
		return Err(std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			"a TSA token is empty or has control characters",
		));
	}
	Ok(token)
}

/// Save `settings` and record the change in the evidence chain, naming
/// the `operator` who made it.
pub fn record_change(
	evidence_root: &Path,
	settings: &Settings,
	operator: &str,
) -> std::io::Result<()> {
	save(evidence_root, settings)?;
	let value = if settings.enabled {
		let urls: Vec<String> = settings
			.authorities
			.iter()
			.map(Authority::display)
			.collect();
		format!("enabled ({}) by {operator}", urls.join(", "))
	} else {
		format!("disabled by {operator}")
	};
	crate::evidence::chain::Chain::open(evidence_root)?.append(
		crate::evidence::record::Entry::Setting(crate::evidence::record::Setting {
			name: "timestamp".into(),
			value: crate::evidence::record::bounded(&value),
		}),
	)?;
	Ok(())
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "settings_tests_fail_closed.rs"]
mod tests_fail_closed;

#[cfg(test)]
#[path = "settings_tests_secrets.rs"]
mod tests_secrets;
