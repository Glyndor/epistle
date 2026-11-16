//! Load-time checks of `[antispam.senders]` and every `[[antispam_scope]]`.

use std::collections::HashSet;

use super::{
	AntispamScope, AttachmentScope, MAX_FIRST_TIME_DELAY_SECS, MAX_GREYLIST_DELAY_SECS, SenderLists,
};
use crate::antispam::sender_lists::{Entry, MAX_ENTRIES};
use crate::config::{AttachmentMode, Config, ConfigError, valid_extension, valid_mime_pattern};

fn invalid(message: String) -> ConfigError {
	ConfigError::Invalid(message)
}

/// Check the entries of one list.
fn check_list(label: &str, key: &str, list: &[String]) -> Result<HashSet<String>, ConfigError> {
	if list.len() > MAX_ENTRIES {
		return Err(invalid(format!(
			"{label} {key} has more than {MAX_ENTRIES} entries"
		)));
	}
	let mut seen = HashSet::new();
	for text in list {
		let entry = Entry::parse(text).map_err(|why| invalid(format!("{label} {key}: {why}")))?;
		seen.insert(format!("{entry:?}"));
	}
	Ok(seen)
}

/// Check the three lists of one scope, and that no entry is both allowed and
/// denied there.
pub(crate) fn check_sender_lists(label: &str, lists: &SenderLists) -> Result<(), ConfigError> {
	let allow = check_list(label, "allow", &lists.allow)?;
	let deny = check_list(label, "deny", &lists.deny)?;
	check_list(label, "deny_recipients", &lists.deny_recipients)?;
	if let Some(both) = allow.intersection(&deny).min() {
		return Err(invalid(format!(
			"{label} {both:?} is in both allow and deny"
		)));
	}
	Ok(())
}

impl Config {
	pub(crate) fn validate_antispam_scopes(&self) -> Result<(), ConfigError> {
		check_sender_lists("[antispam.senders]", &self.antispam.senders)?;
		let mut seen: HashSet<(&'static str, String)> = HashSet::new();
		for scope in &self.antispam_scopes {
			let (kind, name) = self.scope_target(scope)?;
			let label = format!("[[antispam_scope]] {kind} \"{name}\"");
			if !seen.insert((kind, name.to_ascii_lowercase())) {
				return Err(invalid(format!("{label} is declared more than once")));
			}
			check_sender_lists(&format!("{label} senders"), &scope.senders)?;
			self.validate_scope_attachments(&label, &scope.attachments)?;
			Self::validate_scope_numbers(&label, scope)?;
		}
		Ok(())
	}

	/// The one target of `scope`, checked against what the file declares.
	fn scope_target<'a>(
		&self,
		scope: &'a AntispamScope,
	) -> Result<(&'static str, &'a str), ConfigError> {
		let named = [
			("tenant", scope.tenant.as_deref()),
			("domain", scope.domain.as_deref()),
			("account", scope.account.as_deref()),
		];
		let mut targets = named
			.iter()
			.filter_map(|(kind, name)| name.map(|n| (*kind, n)));
		let (Some((kind, name)), None) = (targets.next(), targets.next()) else {
			return Err(invalid(
				"[[antispam_scope]] must name exactly one of tenant, domain or account".into(),
			));
		};
		if name.trim().is_empty() || name.len() > 253 || name.chars().any(char::is_control) {
			return Err(invalid(format!(
				"[[antispam_scope]] {kind} must be a name of 1 to 253 characters"
			)));
		}
		let known = match kind {
			"tenant" => self
				.tenants
				.iter()
				.any(|tenant| tenant.name.as_deref() == Some(name)),
			"domain" => self
				.domains
				.iter()
				.any(|domain| domain.eq_ignore_ascii_case(name)),
			_ => true,
		};
		if !known {
			return Err(invalid(format!(
				"[[antispam_scope]] {kind} \"{name}\" is not declared in the {}",
				if kind == "tenant" {
					"[[tenant]] list"
				} else {
					"domains list"
				}
			)));
		}
		Ok((kind, name))
	}

	/// The thresholds and delays of one scope.
	fn validate_scope_numbers(label: &str, scope: &AntispamScope) -> Result<(), ConfigError> {
		for (key, value) in [
			("bayes_junk_at", scope.bayes_junk_at),
			("bayes_reject_at", scope.bayes_reject_at),
		] {
			if value.is_some_and(|value| !(0.0..=1.0).contains(&value)) {
				return Err(invalid(format!("{label} {key} must be in [0.0, 1.0]")));
			}
		}
		if let (Some(junk), Some(reject)) = (scope.bayes_junk_at, scope.bayes_reject_at)
			&& reject < junk
		{
			return Err(invalid(format!(
				"{label} bayes_reject_at ({reject}) must be at least bayes_junk_at ({junk})"
			)));
		}
		if scope
			.greylist_delay_secs
			.is_some_and(|delay| delay > MAX_GREYLIST_DELAY_SECS)
		{
			return Err(invalid(format!(
				"{label} greylist_delay_secs must be at most {MAX_GREYLIST_DELAY_SECS}"
			)));
		}
		if scope
			.first_time_sender_delay_secs
			.is_some_and(|delay| delay > MAX_FIRST_TIME_DELAY_SECS)
		{
			return Err(invalid(format!(
				"{label} first_time_sender_delay_secs must be at most {MAX_FIRST_TIME_DELAY_SECS}"
			)));
		}
		if scope.forward_per_min == Some(0) {
			return Err(invalid(format!(
				"{label} forward_per_min must be at least 1; remove the key to keep the wider scope's limit"
			)));
		}
		Ok(())
	}

	/// A scope's attachment settings only tighten the server's.
	fn validate_scope_attachments(
		&self,
		label: &str,
		scope: &AttachmentScope,
	) -> Result<(), ConfigError> {
		if scope.is_empty() {
			return Ok(());
		}
		let server = &self.attachments;
		if server.mode == AttachmentMode::Off {
			return Err(invalid(format!(
				"{label} attachments need [attachments] mode other than \"off\": a scope only tightens the server's policy"
			)));
		}
		if scope.block_extensions.len() > crate::config::MAX_EXTENSIONS
			|| scope.block_mime_types.len() > crate::config::MAX_EXTENSIONS
		{
			return Err(invalid(format!("{label} attachments list is too long")));
		}
		if let Some(bad) = scope.block_extensions.iter().find(|e| !valid_extension(e)) {
			return Err(invalid(format!(
				"{label} block_extensions: {bad:?} is not an extension"
			)));
		}
		if let Some(bad) = scope
			.block_mime_types
			.iter()
			.find(|m| !valid_mime_pattern(m))
		{
			return Err(invalid(format!(
				"{label} block_mime_types: {bad:?} is not a type/subtype or type/*"
			)));
		}
		if scope.max_attachment_bytes == Some(0) {
			return Err(invalid(format!("{label} max_attachment_bytes must be > 0")));
		}
		if let Some(mode) = scope.mode
			&& mode < server.mode
		{
			return Err(invalid(format!(
				"{label} mode is weaker than the server's [attachments] mode: a scope only tightens"
			)));
		}
		if let (Some(limit), Some(server_limit)) =
			(scope.max_attachment_bytes, server.max_attachment_bytes)
			&& limit > server_limit
		{
			return Err(invalid(format!(
				"{label} max_attachment_bytes is above the server's {server_limit}: a scope only tightens"
			)));
		}
		if scope.macros.is_some_and(|action| action < server.macros)
			|| scope
				.encrypted_archives
				.is_some_and(|action| action < server.encrypted_archives)
		{
			return Err(invalid(format!(
				"{label} macros or encrypted_archives is weaker than the server's: a scope only tightens"
			)));
		}
		Ok(())
	}
}
