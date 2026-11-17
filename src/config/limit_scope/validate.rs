//! Load-time checks of `[limits]` and every `[[limit_scope]]`: one target
//! per entry, sizes the server can honour, and no scope looser than the
//! one above it.

use std::collections::HashSet;

use super::{Caps, Limit};
use crate::config::{Config, ConfigError};
use crate::limits::{Kind, key};

fn invalid(message: String) -> ConfigError {
	ConfigError::Invalid(message)
}

/// Whether `entry` allows more than `above` does.
fn loosens(entry: Limit, above: Option<Limit>) -> bool {
	match (entry, above) {
		(Limit::Unlimited, Some(Limit::Max(_))) => true,
		(Limit::Max(entry), Some(Limit::Max(above))) => entry > above,
		_ => false,
	}
}

fn show(limit: Limit) -> String {
	match limit {
		Limit::Unlimited => "\"unlimited\"".into(),
		Limit::Max(value) => value.to_string(),
	}
}

impl Config {
	/// The server's `max_message_size` as every scope sees it.
	fn server_message_size(&self) -> u64 {
		match self.max_message_size {
			None | Some(0) => crate::smtp::session::MAX_MESSAGE_SIZE as u64,
			Some(size) => size.max(crate::smtp::session::MIN_MESSAGE_SIZE as u64),
		}
	}

	/// What the scope above `kind` allows, for a scope that has `wider`
	/// between itself and the server (a tenant that owns the domain).
	fn wider_limit(&self, kind: Kind, wider: Option<&Caps>) -> (Option<Limit>, &'static str) {
		if let Some(limit) = wider.and_then(|caps| kind.pick(caps)) {
			return (Some(limit), "the tenant");
		}
		if kind == Kind::MessageSize {
			return (Some(Limit::Max(self.server_message_size())), "the server");
		}
		(kind.server_value(&self.limits), "the server")
	}

	/// Check one scope's caps against the wider scope.
	fn check_caps(
		&self,
		label: &str,
		caps: &Caps,
		wider: Option<&Caps>,
	) -> Result<(), ConfigError> {
		for kind in Kind::ALL {
			let Some(entry) = kind.pick(caps) else {
				continue;
			};
			if let (Kind::MessageSize, Limit::Max(size)) = (kind, entry)
				&& size < crate::smtp::session::MIN_MESSAGE_SIZE as u64
			{
				return Err(invalid(format!(
					"{label} {} is {size}: {}",
					kind.key(),
					crate::smtp::session::MIN_MESSAGE_SIZE_REASON
				)));
			}
			let (above, who) = self.wider_limit(kind, wider);
			if loosens(entry, above) {
				let above = above.map_or_else(String::new, show);
				return Err(invalid(format!(
					"{label} {} is {} but {who} allows {above}: a scope only tightens",
					kind.key(),
					show(entry)
				)));
			}
		}
		Ok(())
	}

	pub(crate) fn validate_limit_scopes(&self) -> Result<(), ConfigError> {
		if self.limits.max_message_size.is_some() {
			return Err(invalid(
				"[limits] max_message_size: the server's cap is the top-level max_message_size; \
				 [[limit_scope]] entries may set it lower"
					.into(),
			));
		}
		let mut seen: HashSet<(&'static str, String)> = HashSet::new();
		for scope in &self.limit_scopes {
			let (kind, name) = self.named_scope_target(
				"[[limit_scope]]",
				(
					scope.tenant.as_deref(),
					scope.domain.as_deref(),
					scope.account.as_deref(),
				),
			)?;
			let label = format!("[[limit_scope]] {kind} \"{name}\"");
			if !seen.insert((kind, name.to_ascii_lowercase())) {
				return Err(invalid(format!("{label} is declared more than once")));
			}
			let wider = (kind == "domain")
				.then(|| self.tenant_caps_of(name))
				.flatten();
			self.check_caps(&label, &scope.caps, wider)?;
		}
		Ok(())
	}

	/// The caps of the `[[limit_scope]]` of the tenant that owns `domain`.
	fn tenant_caps_of(&self, domain: &str) -> Option<&Caps> {
		let domain = key(domain);
		let tenant = self
			.tenants
			.iter()
			.find(|tenant| tenant.domains.iter().any(|owned| key(owned) == domain))?;
		let name = tenant.name.as_deref()?;
		self.limit_scopes
			.iter()
			.find(|scope| scope.tenant.as_deref() == Some(name))
			.map(|scope| &scope.caps)
	}
}
