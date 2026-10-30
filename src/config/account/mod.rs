//! Account definitions: who receives mail at which addresses.

use serde::Deserialize;

use super::Protocol;

/// One mail account.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
	/// Account name; doubles as the mailbox directory name.
	pub name: String,
	/// Addresses delivered to this account.
	pub addresses: Vec<String>,
	/// argon2id password hash (PHC string). Without it the account is
	/// receive-only and cannot authenticate.
	pub password_hash: Option<String>,
	/// Domains for which this account receives mail addressed to otherwise
	/// unknown local users (catch-all). Off by default.
	#[serde(default)]
	pub catch_all: Vec<String>,
	/// Storage quota in bytes for this account. Absent falls back to the
	/// domain quota, then the server default.
	#[serde(default)]
	pub quota_bytes: Option<u64>,
	/// External addresses this account's mail is also forwarded to. Empty
	/// (the default) disables forwarding.
	#[serde(default)]
	pub forward: Vec<String>,
	/// Keep the local copy when forwarding. True (the default) is safe: mail
	/// is never lost. Set false for pure forwarding (no local mailbox copy).
	#[serde(default = "default_true")]
	pub forward_keep_local: bool,
	/// Restrict which authentication protocols this account may sign in
	/// through. `None` (the default) means every protocol the directory
	/// knows about, mirroring the pre-restriction behaviour. When set, only
	/// the listed protocols authenticate this account; every other
	/// password-based path (SMTP submission, IMAP, POP3, ManageSieve, the
	/// API credential-verification endpoint, OAuth approval, WebDAV) rejects
	/// the same way an unknown login does, so the wire response never
	/// reveals that the account exists.
	#[serde(default)]
	pub allowed_protocols: Option<Vec<Protocol>>,
	/// The person's name, free text used as the sender name (JMAP
	/// `Identity.name`, the `From` that `/api/v1/send` builds). Kept as
	/// written, any case and script; trimmed, bounded, no control characters.
	#[serde(default)]
	pub display_name: Option<String>,
}

/// Serde default for boolean fields that default to true.
fn default_true() -> bool {
	true
}

impl Account {
	/// Every forwarding target must be an address epistle can deliver to: a
	/// well-formed local part and a domain with at least one dot. The command
	/// line refuses the same shapes when it writes the target, so a config
	/// file cannot hold a target `epistle account forward add` would not
	/// write.
	pub(crate) fn validate_forward(&self) -> Result<(), String> {
		for target in &self.forward {
			if let Err(why) = crate::util::address_reason::parse(target) {
				return Err(format!(
					"account \"{}\": forward target {target:?}: {why}",
					self.name
				));
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests;
