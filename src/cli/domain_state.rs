//! `epistle domain enable|disable`: switch a hosted domain off without
//! removing it. The switch is the `disabled_domains` array of the
//! configuration file; the server rejects mail for a listed domain like
//! mail for an unknown user and lets nobody send as an address in it.
//! Accounts, mailboxes, aliases, DNS records and DKIM keys are kept.

use super::domain_writers::Commit;
use crate::cli::config_edit::ConfigDocument;
use crate::config::Config;

/// Whether `domain` is configured and not switched off.
pub(super) fn is_enabled(config: &Config, domain: &str) -> bool {
	!config
		.disabled_domains
		.iter()
		.any(|disabled| disabled.eq_ignore_ascii_case(domain))
}

/// Add `domain` to, or drop it from, `disabled_domains`. Refuses to switch
/// off the last enabled domain of a server that has listeners: it would
/// keep accepting connections and reject every recipient.
pub(super) fn set_enabled(
	config: &Config,
	document: &mut ConfigDocument,
	domain: &str,
	enabled: bool,
) -> Result<(), String> {
	let stored = domain.trim().to_ascii_lowercase();
	if enabled {
		let kept = config
			.disabled_domains
			.iter()
			.filter(|disabled| !disabled.eq_ignore_ascii_case(&stored));
		return document.replace_top_array("disabled_domains", strings(kept));
	}
	let remaining = config
		.domains
		.iter()
		.filter(|other| !other.eq_ignore_ascii_case(&stored))
		.filter(|other| is_enabled(config, other))
		.count();
	if remaining == 0 && !config.listeners.is_empty() {
		return Err(format!(
			"cannot disable {domain}: it is the last enabled domain and the server has \
			 listeners; keep one domain enabled"
		));
	}
	document.add_string("disabled_domains", &stored)
}

fn strings<'a>(values: impl Iterator<Item = &'a String>) -> toml_edit::Array {
	values
		.map(|value| toml_edit::Value::from(value.as_str()))
		.collect()
}

/// The commit of `domain enable|disable`.
pub(super) fn commit(domain: &str, enabled: bool) -> Commit<'_> {
	let (verb, action) = if enabled {
		("enabled", "enable")
	} else {
		("disabled", "disable")
	};
	Commit {
		subject: format!("domain {domain}"),
		verb,
		already: verb,
		action,
		fields: serde_json::json!({ "domain": domain, "enabled": enabled }),
		records_for: None,
	}
}
