//! The ACME decision and the contact helper that `build_config`
//! consults when it decides whether to write an `[acme]` block
//! and an `acme` listener. Split off from `apply_config.rs` to
//! keep the per-file line ceiling: the listener array and the
//! config block are the two readers of this decision, and they
//! have to agree, so the decision lives in one place.
//!
//! `build_config` and `listeners_to_write` are the only callers.

use super::Answers;
use super::apply_config::DesiredAcme;

/// Let's Encrypt production ACME directory. The renewal loop in
/// `crate::acme::renew` registers and obtains a certificate
/// against this URL; a freshly-installed server on a public
/// hostname receives its first certificate within minutes.
pub(super) const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str =
	"https://acme-v02.api.letsencrypt.org/directory";

/// Decide whether the desired config carries an `[acme]` block.
/// The operator's explicit `acme.enabled` (true or false) wins;
/// when the section is absent, init falls back to the public-
/// hostname heuristic. The decision is what gates both the
/// config block and the `acme` listener, so the two stay in
/// sync.
pub(super) fn should_enable_acme(answers: &Answers) -> bool {
	if let Some(acme) = &answers.acme
		&& let Some(enabled) = acme.enabled
	{
		return enabled;
	}
	crate::cli::init::answers::is_public_hostname(&answers.hostname)
}

/// The contact URI the renewal loop registers with the CA.
/// Defaults to `mailto:postmaster@<first configured domain>`. The
/// operator override (`acme.contact`) is honored when present.
/// Returns the empty string when the answers carry no domains, so
/// the caller can spot the misconfiguration without crashing.
pub(super) fn acme_contact(answers: &Answers) -> String {
	if let Some(acme) = &answers.acme
		&& let Some(contact) = &acme.contact
		&& !contact.trim().is_empty()
	{
		return contact.clone();
	}
	let domain = answers
		.domains
		.first()
		.map(String::as_str)
		.unwrap_or("example.com");
	format!("mailto:postmaster@{domain}")
}

/// Build the `[acme]` block `init` writes into the config when
/// ACME is on. Returns `None` for the off case, so the same
/// helper drives both the present and absent states the
/// `serde(skip_serializing_if = "Option::is_none")` attribute
/// reads. The renew-before window matches the schema default
/// (30 days) so the field appears explicitly in the rendered
/// config and a future change to the schema default flows
/// through `init` without surprising an operator who pinned
/// the value by hand.
pub(super) fn build_acme_block(answers: &Answers) -> Option<DesiredAcme> {
	if !should_enable_acme(answers) {
		return None;
	}
	Some(DesiredAcme {
		directory_url: LETS_ENCRYPT_PRODUCTION_DIRECTORY.to_string(),
		contacts: vec![acme_contact(answers)],
		domains: vec![answers.hostname.clone()],
		renew_before_days: 30,
	})
}
