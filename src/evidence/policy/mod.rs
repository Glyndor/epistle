//! Which mail keeps evidence, how much of it, and for how long.
//!
//! A rule applies to one class (or every class) within a scope: the whole
//! server, one tenant, or one account. The most specific rule wins: account
//! before tenant before server, and within a scope a rule for the class
//! before a rule for every class. Without any rule, `transactional` keeps
//! metadata for 365 days and the other classes keep no evidence.
//!
//! `transactional` always keeps evidence: a rule may lengthen it or keep the
//! full message, never turn it off.
//!
//! The rules live in `<evidence>/policy.json`, written by `epistle evidence
//! policy set`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::MailClass;
use super::record::{Retention, RetentionMode};

/// Days kept when no rule says otherwise.
pub const DEFAULT_DAYS: u32 = 365;
/// The longest retention a rule may set (25 years).
pub const MAX_DAYS: u32 = 25 * 366;
/// The most rules the policy may hold.
pub const MAX_RULES: usize = 1024;

const FILE: &str = "policy.json";

/// What a rule keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
	/// No evidence.
	Off,
	/// Records and the hash of each message.
	Metadata,
	/// Records and the exact message bytes.
	Full,
}

/// Where a rule applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", content = "name", rename_all = "snake_case")]
pub enum Scope {
	/// Every account.
	Server,
	/// The accounts of one tenant.
	Tenant(String),
	/// One account.
	Account(String),
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
	/// Where it applies.
	#[serde(flatten)]
	pub scope: Scope,
	/// The class, or `None` for every class.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub class: Option<MailClass>,
	/// What it keeps.
	pub mode: Mode,
	/// For how long, in days.
	pub days: u32,
}

/// The whole policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
	/// The rules, in no particular order.
	pub rules: Vec<Rule>,
}

impl Scope {
	fn rank(&self) -> u8 {
		match self {
			Scope::Account(_) => 3,
			Scope::Tenant(_) => 2,
			Scope::Server => 1,
		}
	}

	fn covers(&self, account: &str, tenant: Option<&str>) -> bool {
		match self {
			Scope::Server => true,
			Scope::Tenant(name) => tenant.is_some_and(|tenant| tenant.eq_ignore_ascii_case(name)),
			Scope::Account(name) => name.eq_ignore_ascii_case(account),
		}
	}
}

impl Policy {
	/// The retention for `class` mail from `account` (in `tenant`), or
	/// `None` when no evidence is kept.
	pub fn retention(
		&self,
		account: &str,
		tenant: Option<&str>,
		class: MailClass,
	) -> Option<Retention> {
		let best = self
			.rules
			.iter()
			.filter(|rule| rule.class.is_none_or(|wanted| wanted == class))
			.filter(|rule| rule.scope.covers(account, tenant))
			.max_by_key(|rule| (rule.scope.rank(), rule.class.is_some()));
		let (mode, days) = match best {
			Some(rule) => (rule.mode, rule.days),
			None if class == MailClass::Transactional => (Mode::Metadata, DEFAULT_DAYS),
			None => (Mode::Off, 0),
		};
		let (mode, days) = match (mode, class) {
			// A rule for every class cannot switch transactional evidence off.
			(Mode::Off, MailClass::Transactional) => (RetentionMode::Metadata, DEFAULT_DAYS),
			(Mode::Off, _) => return None,
			(Mode::Metadata, _) => (RetentionMode::Metadata, days),
			(Mode::Full, _) => (RetentionMode::Full, days),
		};
		Some(Retention { mode, days })
	}

	/// Check the rules: bounded in number and days, names in the shape of
	/// account and tenant names, no rule turning transactional evidence off.
	pub fn validate(&self) -> Result<(), String> {
		if self.rules.len() > MAX_RULES {
			return Err(format!("at most {MAX_RULES} evidence rules"));
		}
		for rule in &self.rules {
			if rule.mode != Mode::Off && (rule.days == 0 || rule.days > MAX_DAYS) {
				return Err(format!("days must be between 1 and {MAX_DAYS}"));
			}
			if rule.mode == Mode::Off && rule.class == Some(MailClass::Transactional) {
				return Err("transactional mail always keeps evidence".into());
			}
			match &rule.scope {
				Scope::Server => {}
				Scope::Tenant(name) | Scope::Account(name) => {
					if name.is_empty()
						|| name.len() > 254
						|| !name
							.bytes()
							.all(|byte| byte.is_ascii_graphic() && byte != b'/' && byte != b'\\')
					{
						return Err("a tenant or account name is not valid".into());
					}
				}
			}
		}
		Ok(())
	}

	/// Replace the rule for (`scope`, `class`) with `rule`, or add it.
	pub fn set(&mut self, rule: Rule) {
		self.rules
			.retain(|existing| !(existing.scope == rule.scope && existing.class == rule.class));
		self.rules.push(rule);
	}
}

/// The policy under `evidence_root`: empty (the defaults) when none was set.
pub fn load(evidence_root: &Path) -> std::io::Result<Policy> {
	let Some(bytes) = super::checkpoint::read_bounded(&evidence_root.join(FILE), 1024 * 1024)?
	else {
		return Ok(Policy::default());
	};
	let policy: Policy = serde_json::from_slice(&bytes)
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
	policy
		.validate()
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
	Ok(policy)
}

/// Save `policy` under `evidence_root` after checking it.
pub fn save(evidence_root: &Path, policy: &Policy) -> std::io::Result<()> {
	policy
		.validate()
		.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
	super::chain::create_private_dir(evidence_root)?;
	let bytes = serde_json::to_vec_pretty(policy).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&evidence_root.join(FILE), &bytes)
}

#[cfg(test)]
mod tests;
