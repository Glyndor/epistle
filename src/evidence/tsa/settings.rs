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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authority {
	/// Where RFC 3161 requests are POSTed.
	pub url: String,
	/// Hex SHA-256 of the SubjectPublicKeyInfo of each trusted key.
	pub anchors: Vec<String>,
	/// The policy OID (dotted, `1.2.3.4`) its tokens must carry, when the
	/// operator requires one.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub policy: Option<String>,
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
			}],
		}
	}
}

impl Authority {
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
			check_url(&authority.url)?;
			if authority.anchors.is_empty() || authority.anchors.len() > MAX_ANCHORS {
				return Err(SettingsError(format!(
					"each authority needs 1 to {MAX_ANCHORS} anchors"
				)));
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

/// Refuse a URL that is not `https`, or `http` to loopback.
fn check_url(value: &str) -> Result<(), SettingsError> {
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
		"http" if loopback => Ok(()),
		_ => Err(SettingsError(
			"a timestamp authority URL must be https (http only to loopback)".into(),
		)),
	}
}

/// The settings under `evidence_root`: the defaults when none were saved.
pub fn load(evidence_root: &Path) -> std::io::Result<Settings> {
	let path = evidence_root.join(FILE);
	let Some(bytes) = crate::evidence::checkpoint::read_bounded(&path, 64 * 1024)? else {
		return Ok(Settings::default());
	};
	serde_json::from_slice(&bytes)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
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

#[cfg(test)]
#[path = "settings_tests.rs"]
mod tests;
