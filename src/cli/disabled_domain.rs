//! What the commands that create addresses say about a disabled domain: an
//! address in it can receive nothing and send nothing until the domain is
//! enabled again.

use crate::config::Config;

/// The configured disabled domain `address` is in, if it is in one.
pub(super) fn domain_of<'a>(config: &'a Config, address: &str) -> Option<&'a str> {
	let (_, domain) = address.rsplit_once('@')?;
	config
		.disabled_domains
		.iter()
		.map(String::as_str)
		.find(|disabled| disabled.eq_ignore_ascii_case(domain.trim()))
}

/// The warning for an address created in a disabled domain, if it is in one.
pub(super) fn warning(config: &Config, address: &str) -> Option<String> {
	let domain = domain_of(config, address)?;
	Some(format!(
		"{address} is in the disabled domain {domain}: it receives and sends nothing until \
		 `epistle domain enable {domain}`"
	))
}

/// The refusal for a new mask in a disabled domain.
pub(super) fn refusal(domain: &str) -> String {
	format!("{domain} is disabled; its mail is rejected until `epistle domain enable {domain}`")
}
